/* fetch.c — see fetch.h. HTTPS pattern (esp_http_client + crt_bundle_attach)
 * copied from main/updater.c's fetch_manifest()/download_to_slot() — same
 * component, same TLS setup, already proven working against GitHub-raw and
 * oisd.nl this session. The one deliberate change: this loop resets the task
 * watchdog on every chunk, which updater.c's shorter fetches don't need to.
 */
#include "fetch.h"

#include <stdint.h>
#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_task_wdt.h"

#include "allowlist.h"
#include "hash.h"
#include "parse.h"

static const char *TAG = "fetch";

#define HTTP_TIMEOUT_MS 30000 /* generous: multi-MB public lists, unlike updater.c's small manifest/blob fetch */
#define CHUNK_SIZE      4096
#define LINE_MAX        2048  /* matches parse.c's own PARSE_MAX_LINE; longer lines are dropped either way */

/* Three fixed Kconfig slots (see Kconfig.projbuild) — an empty slot is
 * skipped in the loop below, same as any other dead source. */
static const char *const SOURCE_URLS[] = {
    CONFIG_GENERATOR_SOURCE_URL_1,
    CONFIG_GENERATOR_SOURCE_URL_2,
    CONFIG_GENERATOR_SOURCE_URL_3,
};
#define SOURCE_COUNT (sizeof(SOURCE_URLS) / sizeof(SOURCE_URLS[0]))

/* Static buffers only, matching the project's "no per-query heap
 * allocation" convention (main/dns_sinkhole.c, main/updater.c) — this task
 * fetches sources one at a time, so no sharing hazard. */
static uint8_t s_chunk[CHUNK_SIZE];
static char s_line[LINE_MAX];

typedef struct {
    blocklist_builder_t *builder;
    long lines;
    long added;
} sink_ctx_t;

static void add_sink(const char *domain, size_t len, void *vctx)
{
    sink_ctx_t *ctx = (sink_ctx_t *)vctx;
    if (allowlist_contains(domain_hash(domain, len))) {
        return; /* manual "never block" entry — never even reaches the builder */
    }
    if (blocklist_builder_add(ctx->builder, domain, len)) {
        ctx->added++;
    }
}

/* Streams one source's HTTP response body, splitting on newlines and feeding
 * each complete line to parse_line(). Returns false on any fetch-level
 * failure (connect/status/read) — an empty or near-empty source is NOT a
 * failure here, that's the aggregate min_domains floor's job. */
static bool fetch_one_source(const char *url, sink_ctx_t *ctx)
{
    const esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = HTTP_TIMEOUT_MS,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        ESP_LOGW(TAG, "%s: client init failed", url);
        return false;
    }

    bool ok = false;
    /* DNS + TCP connect + TLS handshake is one blocking call we can't inject
     * periodic resets into — reset right before it so it gets the full
     * watchdog window fresh. Without this, the window is instead whatever
     * was left over from esp_task_wdt_add()/the previous source, which can
     * already be most of the way to WDT_TIMEOUT_S by the time a cold TLS
     * handshake to a new host finishes (this tripped the watchdog on the
     * very first source during testing). */
    esp_task_wdt_reset();
    if (esp_http_client_open(client, 0) != ESP_OK) {
        ESP_LOGW(TAG, "%s: connect failed", url);
        goto out;
    }
    esp_task_wdt_reset();
    esp_http_client_fetch_headers(client);
    const int status = esp_http_client_get_status_code(client);
    if (status != 200) {
        ESP_LOGW(TAG, "%s: HTTP %d", url, status);
        goto out;
    }
    esp_task_wdt_reset();

    {
        size_t line_len = 0;
        bool line_overflowed = false;
        const long lines_before = ctx->lines;

        for (;;) {
            esp_task_wdt_reset(); /* this loop can run for minutes on a large source */
            const int n = esp_http_client_read(client, (char *)s_chunk, sizeof(s_chunk));
            if (n < 0) {
                ESP_LOGW(TAG, "%s: read error", url);
                goto out;
            }
            if (n == 0) {
                break; /* EOF */
            }
            for (int i = 0; i < n; i++) {
                const char c = (char)s_chunk[i];
                if (c == '\n') {
                    if (!line_overflowed) {
                        parse_line(s_line, line_len, add_sink, ctx);
                    }
                    line_len = 0;
                    line_overflowed = false;
                    ctx->lines++;
                } else if (line_len < LINE_MAX) {
                    s_line[line_len++] = c;
                } else {
                    line_overflowed = true; /* line too long — drop, keep scanning for '\n' */
                }
            }
        }
        if (line_len > 0 && !line_overflowed) { /* final line with no trailing newline */
            parse_line(s_line, line_len, add_sink, ctx);
            ctx->lines++;
        }
        ESP_LOGI(TAG, "%s: %ld lines", url, ctx->lines - lines_before);
    }
    ok = true;
out:
    esp_http_client_cleanup(client);
    return ok;
}

blocklist_generate_status_t fetch_and_generate(const blocklist_platform_t *platform,
                                               size_t min_domains,
                                               blocklist_artifact_t *out)
{
    blocklist_builder_t *b = blocklist_builder_create(platform, min_domains);
    if (!b) {
        return BLOCKLIST_GENERATE_ERR_ALLOC;
    }

    sink_ctx_t ctx = { .builder = b, .lines = 0, .added = 0 };
    int ok_sources = 0;
    for (size_t i = 0; i < SOURCE_COUNT; i++) {
        if (SOURCE_URLS[i][0] == '\0') {
            continue; /* disabled slot */
        }
        if (fetch_one_source(SOURCE_URLS[i], &ctx)) {
            ok_sources++;
        } else {
            ESP_LOGW(TAG, "source failed, continuing: %s", SOURCE_URLS[i]);
        }
    }
    ESP_LOGI(TAG, "%d/%zu sources fetched, %ld domains hashed (pre-dedupe)",
             ok_sources, SOURCE_COUNT, ctx.added);

    const blocklist_generate_status_t status = blocklist_builder_finish(b, out);
    blocklist_builder_destroy(b);
    return status;
}
