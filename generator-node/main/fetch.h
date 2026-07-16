/* fetch.h — multi-source HTTPS fetch, streamed straight into a
 * blocklist_builder_t. Watchdog-safe (see fetch.c) — closes a gap
 * main/updater.c's own download loop has (no watchdog feeding), tolerable
 * there only because that fetch is short; this one can run for minutes
 * across several multi-MB public lists.
 */
#pragma once

#include "generate.h"

/* Fetches all configured public blocklist sources over HTTPS, streaming each
 * into a fresh builder, then calls blocklist_builder_finish(). Per-source
 * failures (connect, non-200, read error) are logged and skipped — matches
 * generator/gen.go's fault-tolerance model exactly: only the aggregate
 * min_domains floor (enforced inside finish()) gates success, not "did
 * every source succeed."
 *
 * Must be called from a task already registered with the watchdog
 * (esp_task_wdt_add) — this resets it periodically during long reads but
 * does not add/remove the registration itself.
 */
blocklist_generate_status_t fetch_and_generate(const blocklist_platform_t *platform,
                                               size_t min_domains,
                                               blocklist_artifact_t *out);
