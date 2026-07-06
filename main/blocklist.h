/* blocklist.h — in-PSRAM blocklist with dual flash data slots.
 *
 * The blocklist is a flat, sorted-ascending array of uint64 (little-endian)
 * FNV-1a domain hashes, produced offline by the Go generator (generator/).
 * It is stored in one of two flash data partitions (blk_a / blk_b); the
 * active slot is recorded in NVS together with the blob's count, sha256 and
 * version so it can be re-validated on every boot.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_partition.h"

/* Refuse to activate a suspiciously small list. This is the most important
 * guard: the common failure is a *successful* download of an empty/truncated
 * list from a broken upstream, which the sha256 alone will not catch.
 * The generator enforces the same floor on the publishing side. */
#define BLOCKLIST_MIN_DOMAINS 10000

#define BLOCKLIST_SLOTS       2
#define BLOCKLIST_VERSION_MAX 32

/* Load the active slot recorded in NVS, falling back to the other slot if it
 * fails validation. ESP_FAIL if neither loads — the caller should keep
 * serving (unfiltered) and let the updater fetch a good list. */
esp_err_t blocklist_init(void);

/* Binary search over the in-PSRAM list. Safe to call from the DNS task at
 * any time, including during an update swap. Returns false on an empty
 * list. */
bool blocklist_contains(uint64_t hash);

size_t blocklist_count(void);

/* Version string of the currently served list ("" if none). */
void blocklist_active_version(char out[BLOCKLIST_VERSION_MAX]);

/* Slot the updater should download into (never the one being served). */
int blocklist_inactive_slot(void);

const esp_partition_t *blocklist_slot_partition(int slot);

/* After the updater has written and sha-verified a blob into `slot`: record
 * its metadata in NVS, load it into a fresh PSRAM buffer (re-verifying size,
 * sha256, floor and sortedness), atomically swap it in, and only then mark
 * the slot active in NVS. On any failure the previously served list keeps
 * serving and the NVS active-slot record is untouched. */
esp_err_t blocklist_commit_slot(int slot, size_t count,
                                const uint8_t sha256[32], const char *version);
