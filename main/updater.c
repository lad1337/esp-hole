/* updater.c — poll manifest, download + validate into the inactive slot.
 *
 * Everything here runs in its own low-priority task, completely off to the
 * side of the DNS serve path. The serve path is only touched at the very end
 * via blocklist_commit_slot(), which swaps atomically after full validation.
 */
#include "updater.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "cJSON.h"

#include "blocklist.h"

/* ---- configuration ------------------------------------------------------ */
#define MANIFEST_URL         "http://esphole.local:8080/manifest.json" /* EDIT ME */
#define MANIFEST_FORMAT      2      /* 2 = uint64 LE FNV-1a; bump with the hash */
#define UPDATE_POLL_S        3600   /* how often to check the manifest */
#define UPDATE_FIRST_DELAY_S 15     /* first check shortly after boot */
#define HTTP_TIMEOUT_MS      15000
/* ------------------------------------------------------------------------- */

static const char *TAG = "updater";

/* Static buffers only — this task allocates nothing per cycle except the
 * short-lived cJSON tree for the (size-capped) manifest. */
static char s_manifest[2048];
static uint8_t s_chunk[4096];

typedef struct {
    char version[BLOCKLIST_VERSION_MAX];
    char url[256];
    size_t size;
    size_t count;
    uint8_t sha256[32];
} manifest_t;

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_sha256_hex(const char *hex, uint8_t out[32])
{
    if (hex == NULL || strlen(hex) != 64) {
        return false;
    }
    for (int i = 0; i < 32; i++) {
        const int hi = hex_nibble(hex[2 * i]);
        const int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* GET `url` into s_manifest. Returns body length, or -1. */
static int fetch_manifest(const char *url)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = HTTP_TIMEOUT_MS,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        return -1;
    }

    int len = -1;
    if (esp_http_client_open(client, 0) == ESP_OK) {
        esp_http_client_fetch_headers(client);
        const int status = esp_http_client_get_status_code(client);
        if (status == 200) {
            len = 0;
            while (len < (int)sizeof(s_manifest) - 1) {
                const int n = esp_http_client_read(client, s_manifest + len,
                                                   sizeof(s_manifest) - 1 - len);
                if (n < 0) {
                    len = -1;
                    break;
                }
                if (n == 0) {
                    break;
                }
                len += n;
            }
            if (len >= 0) {
                s_manifest[len] = '\0';
            }
        } else {
            ESP_LOGW(TAG, "manifest fetch: HTTP %d", status);
        }
    } else {
        ESP_LOGW(TAG, "manifest fetch: connect failed");
    }
    esp_http_client_cleanup(client);
    return len;
}

static bool parse_manifest(const char *json, manifest_t *m)
{
    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        ESP_LOGW(TAG, "manifest is not valid JSON");
        return false;
    }

    bool ok = false;
    const cJSON *format = cJSON_GetObjectItem(root, "format");
    const cJSON *version = cJSON_GetObjectItem(root, "version");
    const cJSON *url = cJSON_GetObjectItem(root, "url");
    const cJSON *size = cJSON_GetObjectItem(root, "size");
    const cJSON *count = cJSON_GetObjectItem(root, "count");
    const cJSON *sha = cJSON_GetObjectItem(root, "sha256");

    /* A format mismatch means the publisher hashes differently than this
     * firmware — loading that blob would break every lookup. Refuse. */
    if (!cJSON_IsNumber(format) || (int)format->valuedouble != MANIFEST_FORMAT) {
        ESP_LOGW(TAG, "manifest format %s != %d — firmware/generator mismatch",
                 cJSON_IsNumber(format) ? "mismatch" : "missing", MANIFEST_FORMAT);
        goto out;
    }
    if (!cJSON_IsNumber(size) || !cJSON_IsNumber(count) ||
        !cJSON_IsString(url) || !parse_sha256_hex(cJSON_GetStringValue(sha),
                                                  m->sha256)) {
        ESP_LOGW(TAG, "manifest missing/invalid fields");
        goto out;
    }
    if (cJSON_IsString(version)) {
        strlcpy(m->version, version->valuestring, sizeof(m->version));
    } else if (cJSON_IsNumber(version)) {
        snprintf(m->version, sizeof(m->version), "%.0f", version->valuedouble);
    } else {
        goto out;
    }
    strlcpy(m->url, url->valuestring, sizeof(m->url));
    m->size = (size_t)size->valuedouble;
    m->count = (size_t)count->valuedouble;

    /* Sanity + the MIN_DOMAINS floor. Rejecting here (before any download)
     * keeps a broken generator/publisher from ever reaching flash. */
    if (m->size != m->count * sizeof(uint64_t)) {
        ESP_LOGW(TAG, "manifest size %u != count %u * 8",
                 (unsigned)m->size, (unsigned)m->count);
        goto out;
    }
    if (m->count < BLOCKLIST_MIN_DOMAINS) {
        ESP_LOGW(TAG, "manifest count %u below floor %d — refusing update",
                 (unsigned)m->count, BLOCKLIST_MIN_DOMAINS);
        goto out;
    }
    ok = true;
out:
    cJSON_Delete(root);
    return ok;
}

/* Stream m->url into the given slot's partition, verifying length and sha256
 * as we go. The partition is inactive, so a partial/bad write is harmless. */
static esp_err_t download_to_slot(const manifest_t *m, int slot)
{
    const esp_partition_t *part = blocklist_slot_partition(slot);
    if (part == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    if (m->size > part->size) {
        ESP_LOGW(TAG, "blob (%u bytes) exceeds slot size (%" PRIu32 ")",
                 (unsigned)m->size, part->size);
        return ESP_ERR_INVALID_SIZE;
    }

    const size_t erase_sz =
        (m->size + part->erase_size - 1) & ~(size_t)(part->erase_size - 1);
    esp_err_t err = esp_partition_erase_range(part, 0, erase_sz);
    if (err != ESP_OK) {
        return err;
    }

    esp_http_client_config_t cfg = {
        .url = m->url,
        .timeout_ms = HTTP_TIMEOUT_MS,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        return ESP_ERR_NO_MEM;
    }

    psa_hash_operation_t sha_op = PSA_HASH_OPERATION_INIT;
    if (psa_hash_setup(&sha_op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        goto out;
    }
    esp_http_client_fetch_headers(client);
    if (esp_http_client_get_status_code(client) != 200) {
        ESP_LOGW(TAG, "blob fetch: HTTP %d",
                 esp_http_client_get_status_code(client));
        err = ESP_FAIL;
        goto out;
    }

    size_t written = 0;
    for (;;) {
        const int n = esp_http_client_read(client, (char *)s_chunk, sizeof(s_chunk));
        if (n < 0) {
            err = ESP_FAIL;
            goto out;
        }
        if (n == 0) {
            break;
        }
        if (written + (size_t)n > m->size) {
            ESP_LOGW(TAG, "blob larger than manifest size — rejecting");
            err = ESP_ERR_INVALID_SIZE;
            goto out;
        }
        if (psa_hash_update(&sha_op, s_chunk, (size_t)n) != PSA_SUCCESS) {
            err = ESP_FAIL;
            goto out;
        }
        err = esp_partition_write(part, written, s_chunk, (size_t)n);
        if (err != ESP_OK) {
            goto out;
        }
        written += (size_t)n;
    }

    if (written != m->size) {
        ESP_LOGW(TAG, "truncated download: %u of %u bytes",
                 (unsigned)written, (unsigned)m->size);
        err = ESP_ERR_INVALID_SIZE;
        goto out;
    }

    uint8_t sha_got[32];
    size_t sha_got_len = 0;
    if (psa_hash_finish(&sha_op, sha_got, sizeof(sha_got), &sha_got_len) !=
            PSA_SUCCESS || sha_got_len != sizeof(sha_got)) {
        err = ESP_FAIL;
        goto out;
    }
    if (memcmp(sha_got, m->sha256, sizeof(sha_got)) != 0) {
        ESP_LOGW(TAG, "sha256 mismatch — rejecting download");
        err = ESP_ERR_INVALID_CRC;
        goto out;
    }
    err = ESP_OK;
out:
    psa_hash_abort(&sha_op); /* no-op if the operation already finished */
    esp_http_client_cleanup(client);
    return err;
}

static void check_once(void)
{
    const int len = fetch_manifest(MANIFEST_URL);
    if (len <= 0) {
        return; /* network hiccup — keep serving, retry next cycle */
    }

    manifest_t m;
    memset(&m, 0, sizeof(m));
    if (!parse_manifest(s_manifest, &m)) {
        return;
    }

    char current[BLOCKLIST_VERSION_MAX];
    blocklist_active_version(current);
    if (strcmp(current, m.version) == 0) {
        return; /* already serving this version */
    }

    const int slot = blocklist_inactive_slot();
    ESP_LOGI(TAG, "new version %s (have %s): downloading %u domains to slot %d",
             m.version, current[0] ? current : "(none)", (unsigned)m.count, slot);

    esp_err_t err = download_to_slot(&m, slot);
    if (err == ESP_OK) {
        err = blocklist_commit_slot(slot, m.count, m.sha256, m.version);
    }
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "update to version %s complete", m.version);
    } else {
        ESP_LOGW(TAG, "update failed (%s); keeping current list",
                 esp_err_to_name(err));
    }
}

static void updater_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(UPDATE_FIRST_DELAY_S * 1000));
    for (;;) {
        check_once();
        vTaskDelay(pdMS_TO_TICKS(UPDATE_POLL_S * 1000));
    }
}

void updater_start(void)
{
    /* TLS needs a roomy stack; priority stays below the DNS task so an
     * update can never starve query serving. */
    xTaskCreate(updater_task, "updater", 10240, NULL, 3, NULL);
}
