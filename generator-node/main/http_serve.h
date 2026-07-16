/* http_serve.h — serves the currently-published artifact as GET
 * /manifest.json and GET /blocklist.bin, mirroring generator/server.go's
 * two routes (minus /healthz, already in generator_main.c, and minus
 * /stats, explicitly out of scope per CLAUDE.md's "Firmware roles").
 */
#pragma once

#include "esp_http_server.h"

#include "generate.h"

/* Registers both routes on an already-started httpd instance. Both return
 * 503 until http_serve_publish() has been called at least once. */
void http_serve_register(httpd_handle_t server);

/* Atomically replaces the currently-served artifact — mutex-guarded pointer
 * swap, the same idiom main/blocklist.c uses for its slot swap. Takes
 * ownership of art->blob (freed via realloc_fn, either immediately if this
 * publish is rejected, or later once superseded by the next publish).
 *
 * version is an opaque string only ever compared for equality by consuming
 * sinkhole nodes (see main/updater.c's strcmp against the currently-active
 * version) — it does not need to be a wall-clock timestamp. This firmware
 * has no NTP/SNTP setup (out of scope for serving), so instead of
 * generator/gen.go's UTC-timestamp version, the caller is expected to pass
 * a content-derived identifier (e.g. a hex prefix of art->sha256) — see
 * generator_main.c. This is a strict improvement in one respect: identical
 * content always produces an identical version string automatically,
 * without needing Go's separate explicit "sha256 unchanged, keep old
 * version" short-circuit.
 *
 * url is the manifest's "url" field — the full absolute blob URL, e.g.
 * "http://192.168.1.154:8080/blocklist.bin".
 */
void http_serve_publish(const blocklist_artifact_t *art, const char *version,
                        const char *url, blocklist_realloc_fn realloc_fn);
