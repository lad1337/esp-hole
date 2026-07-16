/* stats.h — best-effort query statistics, reported over UDP using the
 * InfluxDB line protocol (one datagram per interval, delta values).
 *
 * The count functions are lock-free 32-bit counter bumps, safe to call from
 * the DNS serve path. All network I/O lives in a separate low-priority task.
 * With CONFIG_SINKHOLE_STATS_ENABLE=n every call compiles to a no-op, so the
 * callers need no #if guards.
 */
#pragma once

#include <stdint.h>
#include "sdkconfig.h"

#if CONFIG_SINKHOLE_STATS_ENABLE

void stats_count_blocked(void);
void stats_count_forwarded(uint32_t latency_us);
void stats_count_timeout(void);

/* Call once from app_main after the network is up, passing the node's own
 * dotted-quad IPv4 address as the stats "node" identity (and spawns the
 * sender task). */
void stats_start(const char *node_ip);

#else

static inline void stats_count_blocked(void) {}
static inline void stats_count_forwarded(uint32_t latency_us) { (void)latency_us; }
static inline void stats_count_timeout(void) {}
static inline void stats_start(const char *node_ip) { (void)node_ip; }

#endif
