/* allowlist.c — see allowlist.h. */
#include "allowlist.h"

#include <string.h>

#include "esp_log.h"

#include "hash.h"
#include "normalize.h"

#define ALLOWLIST_MAX 32 /* manual exceptions list, not a real blocklist — small fixed cap is plenty */

static const char *TAG = "allowlist";
static uint64_t s_hashes[ALLOWLIST_MAX];
static int s_count;

void allowlist_init(void)
{
    s_count = 0;
    const char *p = CONFIG_GENERATOR_ALLOWLIST;
    while (*p && s_count < ALLOWLIST_MAX) {
        const char *comma = strchr(p, ',');
        const size_t len = comma ? (size_t)(comma - p) : strlen(p);

        char norm[256];
        const size_t n = normalize_domain(p, len, norm, sizeof(norm));
        if (n > 0) {
            s_hashes[s_count++] = domain_hash(norm, n);
            ESP_LOGI(TAG, "allowlisted: %s", norm);
        } else if (len > 0) {
            ESP_LOGW(TAG, "allowlist entry ignored (not a valid domain): %.*s", (int)len, p);
        }
        p = comma ? comma + 1 : p + len;
    }
    if (s_count > 0) {
        ESP_LOGI(TAG, "%d domain(s) allowlisted", s_count);
    }
}

bool allowlist_contains(uint64_t hash)
{
    for (int i = 0; i < s_count; i++) {
        if (s_hashes[i] == hash) {
            return true;
        }
    }
    return false;
}
