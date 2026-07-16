/* artifact_store.h — flash persistence for the published artifact, so a
 * generator-node reboot can keep serving immediately, before a fresh
 * generation completes. Structural mirror of main/blocklist.c's
 * load_slot()/blocklist_commit_slot(), but as the writer: this node
 * produces artifacts, the sinkhole nodes' blocklist.c only ever consumes
 * them. Uses the art_a/art_b partitions (see partitions.csv) — a different
 * subtype (0x41) from the sinkhole's blk_a/blk_b (0x40) so they're never
 * confused, even though these are separate projects/boards.
 */
#pragma once

#include "esp_err.h"

#include "generate.h"

#define ARTIFACT_VERSION_MAX 32

/* Loads whatever was last persisted (if anything) into a fresh
 * platform-allocated buffer, re-validating sha256 + sortedness exactly like
 * main/blocklist.c's load_slot() does for a downloaded blob. ESP_ERR_NOT_FOUND
 * on a first-ever boot with nothing persisted, or if what's there fails
 * validation. On ESP_OK, *out is populated and owned by the caller (free via
 * platform->realloc(out->blob, 0) once superseded, exactly like a freshly
 * generated artifact). */
esp_err_t artifact_store_load(const blocklist_platform_t *platform, blocklist_artifact_t *out,
                              char version_out[ARTIFACT_VERSION_MAX]);

/* Persists a freshly-generated artifact: writes into the *inactive* slot,
 * records size/sha256/version in NVS, re-reads and re-validates that same
 * slot from flash (needs platform->realloc — the readback buffer can be
 * multi-megabyte, same as the artifact itself, so it must come from PSRAM
 * like everything else here), and only then flips the active-slot pointer.
 * On any failure the previously persisted artifact (if any) is untouched —
 * mirrors main/blocklist.c's commit-after-reverify pattern. Does not take
 * ownership of art->blob; the caller keeps it (e.g. to also pass to
 * http_serve_publish()). */
esp_err_t artifact_store_save(const blocklist_platform_t *platform,
                              const blocklist_artifact_t *art, const char *version);
