/* generator_main.c — generator-node firmware entry point.
 *
 * NVS/watchdog init, Ethernet bring-up (net.c), esp_http_server (GET
 * /healthz + http_serve.c's /manifest.json and /blocklist.bin), a boot-time
 * restore of whatever was last persisted (artifact_store.c) so serving
 * resumes immediately, and a periodic fetch+generate+persist+publish cycle
 * (fetch.c + components/blocklist_pipeline/) on CONFIG_GENERATOR_REFRESH_INTERVAL_S.
 * Source URLs, min-domains floor, HTTP port, and public URL base are all
 * Kconfig options (Kconfig.projbuild's "Generator node" menu).
 */
#include <limits.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "nvs_flash.h"

#include "artifact_store.h"
#include "fetch.h"
#include "http_serve.h"
#include "net.h"
#include "platform.h"

/* Must comfortably exceed fetch.c's HTTP_TIMEOUT_MS (30s): a single
 * esp_http_client_read() can legitimately block for that long waiting on a
 * stalled connection (e.g. cable pulled mid-fetch) before the client's own
 * timeout fires — the per-chunk esp_task_wdt_reset() in fetch.c's read loop
 * only guarantees a *fresh* window going into each read, not that any one
 * blocking call finishes inside a shorter window than its own configured
 * timeout. This isn't the sinkhole's tight DNS-serving watchdog (main/
 * dns_sinkhole.c's 10s is deliberately tight to protect the query path) —
 * this node has no comparable hot path, so a generous window costs nothing
 * and avoids a spurious panic-reboot mid-generation on ordinary network
 * hiccups. */
#define WDT_TIMEOUT_S     45
#define REFRESH_FIRST_DELAY_S 10 /* first cycle shortly after boot restore */

static const char *TAG = "generator";
static TaskHandle_t s_refresh_task;

/* Content-derived version (hex prefix of the blob's own sha256) rather than
 * a wall-clock timestamp — this firmware has no NTP setup, and consuming
 * sinkhole nodes only ever compare this string for equality (main/
 * updater.c), never parse it as a date. See http_serve.h for the full
 * reasoning. */
static void build_version(const uint8_t sha256[32], char out[17])
{
    snprintf(out, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
             sha256[0], sha256[1], sha256[2], sha256[3],
             sha256[4], sha256[5], sha256[6], sha256[7]);
}

static void build_url(char *out, size_t out_sz)
{
    if (CONFIG_GENERATOR_PUBLIC_URL_BASE[0] != '\0') {
        snprintf(out, out_sz, "%s/blocklist.bin", CONFIG_GENERATOR_PUBLIC_URL_BASE);
    } else {
        snprintf(out, out_sz, "http://%s:%d/blocklist.bin", net_node_ip(), CONFIG_GENERATOR_HTTP_PORT);
    }
}

static esp_err_t healthz_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_sendstr(req, "ok\n");
}

/* Wakes refresh_task immediately instead of waiting out
 * CONFIG_GENERATOR_REFRESH_INTERVAL_S — same cycle, just triggered on
 * demand. Returns immediately; the cycle itself still runs in refresh_task
 * (a fetch can take minutes, too long to hold an HTTP request open). */
static esp_err_t refresh_handler(httpd_req_t *req)
{
    if (s_refresh_task == NULL) { /* narrow startup window before the task exists */
        httpd_resp_set_status(req, "503 Service Unavailable");
        return httpd_resp_sendstr(req, "not ready yet\n");
    }
    xTaskNotifyGive(s_refresh_task);
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_sendstr(req, "refresh triggered\n");
}

static httpd_handle_t start_http_server(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = CONFIG_GENERATOR_HTTP_PORT;

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed");
        return NULL;
    }

    const httpd_uri_t healthz_uri = {
        .uri = "/healthz",
        .method = HTTP_GET,
        .handler = healthz_handler,
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &healthz_uri));
    const httpd_uri_t refresh_uri = {
        .uri = "/refresh",
        .method = HTTP_GET,
        .handler = refresh_handler,
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &refresh_uri));
    http_serve_register(server); /* /manifest.json, /blocklist.bin — 503 until first publish */
    return server;
}

/* One cycle: fetch+generate, then persist+publish on success. Runs forever
 * on CONFIG_GENERATOR_REFRESH_INTERVAL_S. No sha256-unchanged short-circuit (unlike
 * generator/server.go's refresh()): version is content-derived here (see
 * build_version), so unchanged content already produces an identical
 * version string for consumers with no extra bookkeeping — the only cost of
 * skipping the short-circuit is a redundant flash write every interval,
 * trivial at a multi-hour cadence. */
static void refresh_task(void *arg)
{
    (void)arg;
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));
    vTaskDelay(pdMS_TO_TICKS(REFRESH_FIRST_DELAY_S * 1000));

    for (;;) {
        esp_task_wdt_reset(); /* start each cycle's window fresh */

        blocklist_artifact_t art;
        const blocklist_generate_status_t status =
            fetch_and_generate(&GENERATOR_PLATFORM, CONFIG_GENERATOR_MIN_DOMAINS, &art);

        switch (status) {
        case BLOCKLIST_GENERATE_OK: {
            char version[17];
            build_version(art.sha256, version);
            char url[64];
            build_url(url, sizeof(url));

            /* Persist first (durability), then serve — a failed save is
             * logged and non-fatal: the freshly generated artifact still
             * gets served from memory, it just wouldn't survive a reboot
             * until the next successful save. */
            if (artifact_store_save(&GENERATOR_PLATFORM, &art, version) != ESP_OK) {
                ESP_LOGW(TAG, "failed to persist artifact to flash (serving from memory only)");
            }
            http_serve_publish(&art, version, url, GENERATOR_PLATFORM.realloc);
            break;
        }
        case BLOCKLIST_GENERATE_ERR_ALLOC:
            ESP_LOGE(TAG, "generate failed: allocation error");
            break;
        case BLOCKLIST_GENERATE_ERR_BELOW_MIN_DOMAINS:
            ESP_LOGW(TAG, "generate refused: below the %d-domain floor",
                     CONFIG_GENERATOR_MIN_DOMAINS);
            break;
        case BLOCKLIST_GENERATE_ERR_SELFTEST:
            ESP_LOGE(TAG, "generate failed: self-test inconsistency (bug)");
            break;
        }

        /* Waits out the interval, but /refresh's xTaskNotifyGive() wakes this
         * early — clear any notifications queued during the cycle just run
         * so a /refresh hit mid-cycle doesn't cause an extra immediate loop. */
        ulTaskNotifyValueClear(NULL, ULONG_MAX);
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(CONFIG_GENERATOR_REFRESH_INTERVAL_S * 1000));
    }
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(err);
    }

    const esp_task_wdt_config_t wdt_cfg = {
        .timeout_ms = WDT_TIMEOUT_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    if (esp_task_wdt_reconfigure(&wdt_cfg) != ESP_OK) {
        ESP_ERROR_CHECK(esp_task_wdt_init(&wdt_cfg));
    }

    net_start();
    ESP_LOGI(TAG, "waiting for Ethernet...");
    net_wait_for_ip();
    ESP_LOGI(TAG, "got IP %s", net_node_ip());

    if (start_http_server() != NULL) {
        ESP_LOGI(TAG, "serving on :%d (GET /healthz)", CONFIG_GENERATOR_HTTP_PORT);
    }

    /* Restore whatever was last persisted, if anything, so /manifest.json
     * and /blocklist.bin answer immediately — well before the first fresh
     * generation (which can take several minutes) completes. */
    blocklist_artifact_t restored;
    char restored_version[ARTIFACT_VERSION_MAX];
    if (artifact_store_load(&GENERATOR_PLATFORM, &restored, restored_version) == ESP_OK) {
        char url[64];
        build_url(url, sizeof(url));
        http_serve_publish(&restored, restored_version, url, GENERATOR_PLATFORM.realloc);
    } else {
        ESP_LOGI(TAG, "no persisted artifact to restore");
    }

    /* Same stack size and below-httpd priority as main/updater.c's own
     * update task (10240, prio 3) — TLS handshakes are the dominant stack
     * user, and a long generation cycle must never starve HTTP serving. */
    xTaskCreate(refresh_task, "refresh", 10240, NULL, 3, &s_refresh_task);
}
