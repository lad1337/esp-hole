/* updater.h — blocklist self-update task.
 *
 * Polls a manifest.json at a static URL and, when the version changes,
 * downloads the new blocklist.bin into the inactive data slot, validates it
 * (sha256 + size + minimum count) and hands it to blocklist_commit_slot for
 * the atomic swap. Failures leave the currently served list untouched; the
 * next poll cycle retries. List updates never touch the firmware partitions.
 */
#pragma once

void updater_start(void);
