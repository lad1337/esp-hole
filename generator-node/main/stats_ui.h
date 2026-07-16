/* stats_ui.h — best-effort UDP node-stats collector + a simple /stats page.
 *
 * Consumes the exact wire format main/stats.c already sends (InfluxDB line
 * protocol, one datagram per sinkhole node per interval — see that file's
 * snprintf format string) — the same protocol generator/stats.go already
 * parses, so no sinkhole-side change is needed, just pointing
 * CONFIG_SINKHOLE_STATS_HOST at this node's IP and CONFIG_SINKHOLE_STATS_PORT
 * at GENERATOR_STATS_PORT.
 *
 * Lazy by design (ponytail): cumulative per-node totals since this node's own
 * boot, not generator/stats.go's per-minute ring-buffer time series — no
 * charts, just current numbers. A malformed/garbage datagram is dropped
 * silently; a full node table never blocks fetch/generate/serve. See
 * CLAUDE.md: stats must stay fire-and-forget.
 */
#pragma once

#include "esp_http_server.h"
#include "sdkconfig.h"

#if CONFIG_GENERATOR_STATS_ENABLE

/* Starts the UDP listener task and registers GET /stats (JSON) + GET
 * /stats/ui/ (a small static HTML page) on the given httpd instance. */
void stats_ui_start(httpd_handle_t server);

#else

static inline void stats_ui_start(httpd_handle_t server) { (void)server; }

#endif
