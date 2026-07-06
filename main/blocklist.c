/* blocklist.c — dual-slot blocklist storage and lookup.
 *
 * Reliability rules (see CLAUDE.md):
 *  - the blob is allocated once per load in PSRAM; the DNS hot path never
 *    allocates,
 *  - every load re-validates count floor, sha256 and sortedness, so a
 *    corrupted flash slot can never be served,
 *  - swaps are atomic under a mutex whose hold time is microseconds; the
 *    lookup fails *open* (not blocked) if the lock is ever unavailable,
 *    because serving unfiltered DNS beats serving no DNS.
 */
#include "blocklist.h"

#include <inttypes.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "blocklist";

static const char *SLOT_PART_NAME[BLOCKLIST_SLOTS] = { "blk_a", "blk_b" };

static SemaphoreHandle_t s_lock;
static nvs_handle_t s_nvs;
static uint64_t *s_hashes;                     /* PSRAM, sorted ascending */
static size_t s_count;
static int s_active = -1;
static char s_version[BLOCKLIST_VERSION_MAX];

const esp_partition_t *blocklist_slot_partition(int slot)
{
    if (slot < 0 || slot >= BLOCKLIST_SLOTS) {
        return NULL;
    }
    return esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                    ESP_PARTITION_SUBTYPE_ANY,
                                    SLOT_PART_NAME[slot]);
}

/* Load one slot into a fresh PSRAM buffer, validate it fully, and swap it in.
 * The slot's expected count/sha256/version are read from NVS (written by
 * blocklist_commit_slot after a verified download). */
static esp_err_t load_slot(int slot)
{
    char key[8];
    uint32_t count = 0;
    snprintf(key, sizeof(key), "cnt_%d", slot);
    if (nvs_get_u32(s_nvs, key, &count) != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t sha_want[32];
    size_t sha_len = sizeof(sha_want);
    snprintf(key, sizeof(key), "sha_%d", slot);
    if (nvs_get_blob(s_nvs, key, sha_want, &sha_len) != ESP_OK || sha_len != 32) {
        return ESP_ERR_NOT_FOUND;
    }

    char version[BLOCKLIST_VERSION_MAX] = "";
    size_t ver_len = sizeof(version);
    snprintf(key, sizeof(key), "ver_%d", slot);
    nvs_get_str(s_nvs, key, version, &ver_len);

    const esp_partition_t *part = blocklist_slot_partition(slot);
    if (part == NULL) {
        ESP_LOGE(TAG, "partition %s missing — check partitions.csv",
                 SLOT_PART_NAME[slot]);
        return ESP_ERR_NOT_FOUND;
    }

    const size_t bytes = (size_t)count * sizeof(uint64_t);
    if (count < BLOCKLIST_MIN_DOMAINS || bytes > part->size) {
        ESP_LOGE(TAG, "slot %d count %" PRIu32 " out of range", slot, count);
        return ESP_ERR_INVALID_SIZE;
    }

    uint64_t *buf = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
    if (buf == NULL) {
        ESP_LOGE(TAG, "no PSRAM for %u-entry list", (unsigned)count);
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = esp_partition_read(part, 0, buf, bytes);
    if (err != ESP_OK) {
        goto fail;
    }

    uint8_t sha_got[32];
    size_t sha_got_len = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)buf, bytes,
                         sha_got, sizeof(sha_got), &sha_got_len) != PSA_SUCCESS ||
        sha_got_len != sizeof(sha_got)) {
        err = ESP_FAIL;
        goto fail;
    }
    if (memcmp(sha_got, sha_want, sizeof(sha_got)) != 0) {
        ESP_LOGE(TAG, "slot %d sha256 mismatch (flash corruption?)", slot);
        err = ESP_ERR_INVALID_CRC;
        goto fail;
    }

    /* The generator sorts and dedupes; the device only verifies. A blob that
     * is not strictly ascending would silently break binary search. */
    for (size_t i = 1; i < count; i++) {
        if (buf[i - 1] >= buf[i]) {
            ESP_LOGE(TAG, "slot %d not sorted at index %u", slot, (unsigned)i);
            err = ESP_ERR_INVALID_STATE;
            goto fail;
        }
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint64_t *old = s_hashes;
    s_hashes = buf;
    s_count = count;
    xSemaphoreGive(s_lock);
    free(old); /* safe: no reader can still hold it once the lock cycled */

    s_active = slot;
    strlcpy(s_version, version, sizeof(s_version));
    ESP_LOGI(TAG, "serving slot %d: %u domains, version %s",
             slot, (unsigned)count, s_version[0] ? s_version : "(unset)");
    return ESP_OK;

fail:
    free(buf);
    return err;
}

esp_err_t blocklist_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    configASSERT(s_lock != NULL);
    /* PSA must be initialized before any hash call; idempotent. */
    configASSERT(psa_crypto_init() == PSA_SUCCESS);
    ESP_ERROR_CHECK(nvs_open("blocklist", NVS_READWRITE, &s_nvs));

    uint8_t active = 0xFF;
    nvs_get_u8(s_nvs, "active", &active);

    if (active < BLOCKLIST_SLOTS && load_slot(active) == ESP_OK) {
        return ESP_OK;
    }

    /* Boot fallback: the recorded slot failed validation — try the other
     * one, and if it works record it so the next boot goes straight there. */
    for (int slot = 0; slot < BLOCKLIST_SLOTS; slot++) {
        if (slot == active) {
            continue;
        }
        if (load_slot(slot) == ESP_OK) {
            ESP_LOGW(TAG, "fell back from slot %d to slot %d", active, slot);
            nvs_set_u8(s_nvs, "active", slot);
            nvs_commit(s_nvs);
            return ESP_OK;
        }
    }
    return ESP_FAIL;
}

bool blocklist_contains(uint64_t hash)
{
    /* Real hold times on this lock are microseconds. If it is unavailable
     * for 20 ms something is badly wrong — fail open and keep answering. */
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(20)) != pdTRUE) {
        return false;
    }
    bool found = false;
    size_t lo = 0;
    size_t hi = s_count;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const uint64_t v = s_hashes[mid];
        if (v == hash) {
            found = true;
            break;
        }
        if (v < hash) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    xSemaphoreGive(s_lock);
    return found;
}

size_t blocklist_count(void)
{
    return s_count;
}

void blocklist_active_version(char out[BLOCKLIST_VERSION_MAX])
{
    strlcpy(out, s_version, BLOCKLIST_VERSION_MAX);
}

int blocklist_inactive_slot(void)
{
    return (s_active == 0) ? 1 : 0;
}

esp_err_t blocklist_commit_slot(int slot, size_t count,
                                const uint8_t sha256[32], const char *version)
{
    if (slot < 0 || slot >= BLOCKLIST_SLOTS || slot == s_active) {
        return ESP_ERR_INVALID_ARG;
    }

    char key[8];
    snprintf(key, sizeof(key), "cnt_%d", slot);
    esp_err_t err = nvs_set_u32(s_nvs, key, (uint32_t)count);
    if (err == ESP_OK) {
        snprintf(key, sizeof(key), "sha_%d", slot);
        err = nvs_set_blob(s_nvs, key, sha256, 32);
    }
    if (err == ESP_OK) {
        snprintf(key, sizeof(key), "ver_%d", slot);
        err = nvs_set_str(s_nvs, key, version);
    }
    if (err == ESP_OK) {
        err = nvs_commit(s_nvs);
    }
    if (err != ESP_OK) {
        return err;
    }

    /* Full re-validation + atomic swap. If this fails, NVS "active" still
     * points at the old slot, so both this session and the next boot keep
     * serving the previous list. */
    err = load_slot(slot);
    if (err != ESP_OK) {
        return err;
    }

    nvs_set_u8(s_nvs, "active", slot);
    return nvs_commit(s_nvs);
}
