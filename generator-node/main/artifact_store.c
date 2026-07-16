/* artifact_store.c — see artifact_store.h. Structural mirror of
 * main/blocklist.c's load_slot()/blocklist_commit_slot(); read that file's
 * top-of-file comment for the reliability rules this mirrors (re-validate
 * everything on every load, atomic swap only after full re-verification).
 */
#include "artifact_store.h"

#include <inttypes.h>
#include <string.h>

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_task_wdt.h"
#include "nvs.h"
#include "nvs_flash.h"

#define ARTIFACT_SLOTS 2

static const char *TAG = "artifact_store";
static const char *const SLOT_PART_NAME[ARTIFACT_SLOTS] = { "art_a", "art_b" };

static const esp_partition_t *slot_partition(int slot)
{
    if (slot < 0 || slot >= ARTIFACT_SLOTS) {
        return NULL;
    }
    return esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
                                    SLOT_PART_NAME[slot]);
}

static esp_err_t nvs_open_artifact(nvs_handle_t *out)
{
    return nvs_open("artifact", NVS_READWRITE, out);
}

esp_err_t artifact_store_load(const blocklist_platform_t *platform, blocklist_artifact_t *out,
                              char version_out[ARTIFACT_VERSION_MAX])
{
    memset(out, 0, sizeof(*out));
    version_out[0] = '\0';

    nvs_handle_t nvs;
    esp_err_t err = nvs_open_artifact(&nvs);
    if (err != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t active = 0xFF;
    nvs_get_u8(nvs, "active", &active);
    if (active >= ARTIFACT_SLOTS) {
        nvs_close(nvs);
        return ESP_ERR_NOT_FOUND; /* nothing ever persisted */
    }

    char key[8];
    uint32_t count = 0;
    snprintf(key, sizeof(key), "cnt_%d", active);
    if (nvs_get_u32(nvs, key, &count) != ESP_OK) {
        nvs_close(nvs);
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t sha256[32];
    size_t sha_len = sizeof(sha256);
    snprintf(key, sizeof(key), "sha_%d", active);
    if (nvs_get_blob(nvs, key, sha256, &sha_len) != ESP_OK || sha_len != sizeof(sha256)) {
        nvs_close(nvs);
        return ESP_ERR_NOT_FOUND;
    }

    size_t ver_len = ARTIFACT_VERSION_MAX;
    snprintf(key, sizeof(key), "ver_%d", active);
    nvs_get_str(nvs, key, version_out, &ver_len);
    nvs_close(nvs);

    const esp_partition_t *part = slot_partition(active);
    if (part == NULL) {
        ESP_LOGE(TAG, "partition %s missing — check partitions.csv", SLOT_PART_NAME[active]);
        return ESP_ERR_NOT_FOUND;
    }

    const size_t blob_len = (size_t)count * 8;
    if (blob_len == 0 || blob_len > part->size) {
        ESP_LOGE(TAG, "slot %d size %u out of range", active, (unsigned)blob_len);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t *blob = platform->realloc(NULL, blob_len);
    if (blob == NULL) {
        ESP_LOGE(TAG, "no PSRAM for %u-byte persisted artifact", (unsigned)blob_len);
        return ESP_ERR_NO_MEM;
    }
    if (esp_partition_read(part, 0, blob, blob_len) != ESP_OK) {
        platform->realloc(blob, 0);
        return ESP_FAIL;
    }
    if (!blocklist_verify_blob(blob, blob_len, count, sha256, platform->sha256)) {
        ESP_LOGE(TAG, "slot %d failed re-validation (flash corruption?)", active);
        platform->realloc(blob, 0);
        return ESP_ERR_INVALID_CRC;
    }

    out->blob = blob;
    out->blob_len = blob_len;
    out->count = count;
    memcpy(out->sha256, sha256, sizeof(sha256));
    ESP_LOGI(TAG, "restored slot %d: %u domains, version %s",
             active, (unsigned)count, version_out[0] ? version_out : "(unset)");
    return ESP_OK;
}

esp_err_t artifact_store_save(const blocklist_platform_t *platform,
                              const blocklist_artifact_t *art, const char *version)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open_artifact(&nvs);
    if (err != ESP_OK) {
        return err;
    }

    uint8_t active = 0xFF;
    nvs_get_u8(nvs, "active", &active);
    const int slot = (active == 0) ? 1 : 0; /* inactive slot; slot 0 if nothing active yet */

    const esp_partition_t *part = slot_partition(slot);
    if (part == NULL) {
        nvs_close(nvs);
        ESP_LOGE(TAG, "partition %s missing — check partitions.csv", SLOT_PART_NAME[slot]);
        return ESP_ERR_NOT_FOUND;
    }
    if (art->blob_len > part->size) {
        nvs_close(nvs);
        ESP_LOGE(TAG, "artifact (%u bytes) exceeds slot size (%" PRIu32 ")",
                 (unsigned)art->blob_len, part->size);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_task_wdt_reset(); /* fresh window before erase+write of a multi-MB blob */
    const size_t erase_sz =
        (art->blob_len + part->erase_size - 1) & ~(size_t)(part->erase_size - 1);
    err = esp_partition_erase_range(part, 0, erase_sz);
    if (err == ESP_OK) {
        err = esp_partition_write(part, 0, art->blob, art->blob_len);
    }
    if (err != ESP_OK) {
        nvs_close(nvs);
        return err;
    }

    char key[8];
    snprintf(key, sizeof(key), "cnt_%d", slot);
    err = nvs_set_u32(nvs, key, (uint32_t)art->count);
    if (err == ESP_OK) {
        snprintf(key, sizeof(key), "sha_%d", slot);
        err = nvs_set_blob(nvs, key, art->sha256, sizeof(art->sha256));
    }
    if (err == ESP_OK) {
        snprintf(key, sizeof(key), "ver_%d", slot);
        err = nvs_set_str(nvs, key, version);
    }
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    if (err != ESP_OK) {
        nvs_close(nvs);
        return err;
    }

    /* Re-read what was actually written back from flash and re-validate
     * (sha256 recomputed from the readback bytes + strict-ascending check),
     * exactly like main/blocklist.c's load_slot() does for a downloaded
     * blob — only flip the active pointer once that independently confirms
     * the write landed correctly. The readback buffer can be multi-MB, so
     * like the artifact itself it comes from PSRAM via the platform, not
     * plain malloc(). */
    esp_task_wdt_reset(); /* fresh window before the readback + sha256 recompute */
    uint8_t *readback = platform->realloc(NULL, art->blob_len);
    if (readback == NULL) {
        nvs_close(nvs);
        return ESP_ERR_NO_MEM;
    }
    err = esp_partition_read(part, 0, readback, art->blob_len);
    const bool ok = (err == ESP_OK) &&
                    blocklist_verify_blob(readback, art->blob_len, art->count,
                                          art->sha256, platform->sha256);
    platform->realloc(readback, 0);
    if (!ok) {
        nvs_close(nvs);
        ESP_LOGE(TAG, "slot %d failed post-write re-validation — not activating", slot);
        return ESP_ERR_INVALID_STATE;
    }

    err = nvs_set_u8(nvs, "active", (uint8_t)slot);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return err;
}
