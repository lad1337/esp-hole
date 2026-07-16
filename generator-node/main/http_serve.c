/* http_serve.c — see http_serve.h. */
#include "http_serve.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "blocklist_format.h"

static const char *TAG = "http_serve";

typedef struct {
    uint8_t *blob;
    size_t blob_len;
    char *manifest_json;
    size_t manifest_json_len;
    blocklist_realloc_fn realloc_fn; /* to free blob when superseded */
} published_t;

/* Held across the full response send for both routes, not just the pointer
 * swap — simpler than reference-counting the artifact, and cheap at this
 * project's actual scale (a handful of sinkhole nodes polling hourly, one
 * publish every few hours). A slow client's /blocklist.bin download can
 * delay the next publish by however long that download takes; acceptable
 * here, would not be at higher concurrency/frequency. */
static SemaphoreHandle_t s_lock;
static published_t *s_current; /* NULL until the first publish */

static void published_free(published_t *p)
{
    if (!p) {
        return;
    }
    if (p->blob) {
        p->realloc_fn(p->blob, 0);
    }
    cJSON_free(p->manifest_json);
    free(p);
}

static char *build_manifest_json(const blocklist_artifact_t *art, const char *version,
                                 const char *url, size_t *out_len)
{
    char sha256_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(sha256_hex + i * 2, 3, "%02x", art->sha256[i]);
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    cJSON_AddNumberToObject(root, "format", BLOCKLIST_MANIFEST_FORMAT);
    cJSON_AddStringToObject(root, "version", version);
    cJSON_AddNumberToObject(root, "size", (double)art->blob_len);
    cJSON_AddStringToObject(root, "sha256", sha256_hex);
    cJSON_AddNumberToObject(root, "count", (double)art->count);
    cJSON_AddStringToObject(root, "url", url);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json && out_len) {
        *out_len = strlen(json);
    }
    return json;
}

void http_serve_publish(const blocklist_artifact_t *art, const char *version,
                        const char *url, blocklist_realloc_fn realloc_fn)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }

    published_t *next = malloc(sizeof(*next));
    if (!next) {
        ESP_LOGE(TAG, "publish failed: out of memory for published_t");
        realloc_fn(art->blob, 0);
        return;
    }
    next->blob = art->blob;
    next->blob_len = art->blob_len;
    next->realloc_fn = realloc_fn;
    next->manifest_json = build_manifest_json(art, version, url, &next->manifest_json_len);
    if (!next->manifest_json) {
        ESP_LOGE(TAG, "publish failed: manifest JSON encode failed");
        realloc_fn(art->blob, 0);
        free(next);
        return;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    published_t *old = s_current;
    s_current = next;
    xSemaphoreGive(s_lock);

    published_free(old); /* safe: no reader can still hold `old` once the lock cycled */
    ESP_LOGI(TAG, "published version %s: %zu domains, %zu bytes", version, art->count, art->blob_len);
}

static esp_err_t serve_unavailable(httpd_req_t *req)
{
    httpd_resp_set_status(req, "503 Service Unavailable");
    return httpd_resp_sendstr(req, "no blocklist generated yet\n");
}

static esp_err_t manifest_handler(httpd_req_t *req)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (!s_current) {
        xSemaphoreGive(s_lock);
        return serve_unavailable(req);
    }
    httpd_resp_set_type(req, "application/json");
    const esp_err_t err = httpd_resp_send(req, s_current->manifest_json,
                                          (ssize_t)s_current->manifest_json_len);
    xSemaphoreGive(s_lock);
    return err;
}

static esp_err_t blocklist_handler(httpd_req_t *req)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (!s_current) {
        xSemaphoreGive(s_lock);
        return serve_unavailable(req);
    }
    httpd_resp_set_type(req, "application/octet-stream");
    const esp_err_t err = httpd_resp_send(req, (const char *)s_current->blob,
                                          (ssize_t)s_current->blob_len);
    xSemaphoreGive(s_lock);
    return err;
}

void http_serve_register(httpd_handle_t server)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    const httpd_uri_t manifest_uri = {
        .uri = "/manifest.json",
        .method = HTTP_GET,
        .handler = manifest_handler,
    };
    const httpd_uri_t blocklist_uri = {
        .uri = "/blocklist.bin",
        .method = HTTP_GET,
        .handler = blocklist_handler,
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &manifest_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &blocklist_uri));
}
