/* stats.c — aggregate query stats in static RAM, report over UDP.
 *
 * The DNS task increments cumulative counters (lock-free); this module's own
 * low-priority task snapshots them every CONFIG_SINKHOLE_STATS_INTERVAL_S,
 * computes the interval's deltas, and sends them as one InfluxDB-line-
 * protocol datagram. Every failure — resolution, socket, send — is a silent
 * drop of that interval: monitoring must never affect serving.
 */
#include "stats.h"

#if CONFIG_SINKHOLE_STATS_ENABLE

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static const char *TAG = "stats";

#define STATS_HIST_BUCKETS 16
#define STATS_FIRST_DELAY_MS 5000    /* let DHCP/DNS settle after boot */
#define STATS_RERESOLVE_S 3600       /* re-resolve the host every hour */

/* Cumulative counters, written by the DNS task, read by the stats task.
 * 32-bit relaxed atomics are lock-free on both targets (Xtensa ESP32 and
 * RISC-V ESP32-P4) — nothing here can ever stall the serve path. 64-bit
 * atomics are deliberately avoided: they fall back to lock-based helpers.
 *
 * Wraparound: the sender computes deltas by unsigned subtraction, which is
 * exact across a single uint32 wrap. The serve loop is serial (it blocks on
 * one upstream query at a time), so lat_sum grows at most ~10^6 us per wall
 * second — many orders of magnitude below a double wrap per interval. */
static _Atomic uint32_t s_blocked;
static _Atomic uint32_t s_forwarded;
static _Atomic uint32_t s_timeouts;
static _Atomic uint32_t s_lat_sum_us;
static _Atomic uint32_t s_hist[STATS_HIST_BUCKETS];

/* log2-spaced latency buckets: bucket = bit_length(us) - 7, clamped to
 * [0,15]. Bucket 0 = <128 us, 4 = 1-2 ms, 8 = 16-32 ms, 15 = >2.1 s.
 * latBucketUpper in generator/stats.go hardcodes the same edges — change
 * both together. */
static inline int lat_bucket(uint32_t us)
{
    const int b = (32 - __builtin_clz(us | 1)) - 7;
    return b < 0 ? 0 : (b > 15 ? 15 : b);
}

void stats_count_blocked(void)
{
    atomic_fetch_add_explicit(&s_blocked, 1, memory_order_relaxed);
}

void stats_count_timeout(void)
{
    atomic_fetch_add_explicit(&s_timeouts, 1, memory_order_relaxed);
}

void stats_count_forwarded(uint32_t latency_us)
{
    atomic_fetch_add_explicit(&s_forwarded, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_lat_sum_us, latency_us, memory_order_relaxed);
    atomic_fetch_add_explicit(&s_hist[lat_bucket(latency_us)], 1,
                              memory_order_relaxed);
}

/* ---- sender task --------------------------------------------------------- */

typedef struct {
    uint32_t blocked, forwarded, timeouts, lat_sum_us;
    uint32_t hist[STATS_HIST_BUCKETS];
} stats_snap_t;

/* Static state only — no allocation, matching the rest of the firmware. */
static char s_node[16];              /* dotted-quad IPv4, e.g. "192.168.1.154" */
static char s_line[512];
static int s_sock = -1;
static struct sockaddr_in s_target;
static bool s_target_valid = false;

static void snap_counters(stats_snap_t *out)
{
    out->blocked = atomic_load_explicit(&s_blocked, memory_order_relaxed);
    out->forwarded = atomic_load_explicit(&s_forwarded, memory_order_relaxed);
    out->timeouts = atomic_load_explicit(&s_timeouts, memory_order_relaxed);
    out->lat_sum_us = atomic_load_explicit(&s_lat_sum_us, memory_order_relaxed);
    for (int i = 0; i < STATS_HIST_BUCKETS; i++) {
        out->hist[i] = atomic_load_explicit(&s_hist[i], memory_order_relaxed);
    }
}

/* Resolve CONFIG_SINKHOLE_STATS_HOST into s_target. getaddrinfo may block
 * for a few seconds on a dead DNS — harmless at this task's priority. */
static bool resolve_target(void)
{
    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *res = NULL;
    if (getaddrinfo(CONFIG_SINKHOLE_STATS_HOST, NULL, &hints, &res) != 0 ||
        res == NULL) {
        return false;
    }
    memcpy(&s_target, res->ai_addr, sizeof(s_target));
    s_target.sin_port = htons(CONFIG_SINKHOLE_STATS_PORT);
    freeaddrinfo(res);
    return true;
}

static void stats_send_once(stats_snap_t *last, int64_t *last_resolve_us)
{
    /* Snapshot and advance unconditionally: a failed send drops this
     * interval's data rather than accumulating a backlog that would land
     * as a spike later. */
    stats_snap_t cur, d;
    snap_counters(&cur);
    d.blocked = cur.blocked - last->blocked;
    d.forwarded = cur.forwarded - last->forwarded;
    d.timeouts = cur.timeouts - last->timeouts;
    d.lat_sum_us = cur.lat_sum_us - last->lat_sum_us;
    for (int i = 0; i < STATS_HIST_BUCKETS; i++) {
        d.hist[i] = cur.hist[i] - last->hist[i];
    }
    *last = cur;

    if (s_sock < 0) {
        s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (s_sock < 0) {
            return; /* retry next interval */
        }
    }

    const int64_t now = esp_timer_get_time();
    if (!s_target_valid || now - *last_resolve_us > STATS_RERESOLVE_S * 1000000LL) {
        s_target_valid = resolve_target();
        if (!s_target_valid) {
            return; /* drop this interval, retry next */
        }
        *last_resolve_us = now;
    }

    /* No timestamp on the line: nodes are clockless, the server stamps on
     * arrival. Counts are interval deltas; uptime_s is a gauge so reboots
     * are visible in the UI. */
    const int len = snprintf(s_line, sizeof(s_line),
        "esphole,node=%s blocked=%" PRIu32 "i,forwarded=%" PRIu32 "i,"
        "timeouts=%" PRIu32 "i,lat_sum_us=%" PRIu32 "i,uptime_s=%lldi,"
        "h0=%" PRIu32 "i,h1=%" PRIu32 "i,h2=%" PRIu32 "i,h3=%" PRIu32 "i,"
        "h4=%" PRIu32 "i,h5=%" PRIu32 "i,h6=%" PRIu32 "i,h7=%" PRIu32 "i,"
        "h8=%" PRIu32 "i,h9=%" PRIu32 "i,h10=%" PRIu32 "i,h11=%" PRIu32 "i,"
        "h12=%" PRIu32 "i,h13=%" PRIu32 "i,h14=%" PRIu32 "i,h15=%" PRIu32 "i",
        s_node, d.blocked, d.forwarded, d.timeouts, d.lat_sum_us,
        (long long)(esp_timer_get_time() / 1000000),
        d.hist[0], d.hist[1], d.hist[2], d.hist[3],
        d.hist[4], d.hist[5], d.hist[6], d.hist[7],
        d.hist[8], d.hist[9], d.hist[10], d.hist[11],
        d.hist[12], d.hist[13], d.hist[14], d.hist[15]);
    if (len <= 0 || len >= (int)sizeof(s_line)) {
        return; /* cannot happen: worst case is ~340 bytes */
    }

    /* Best-effort by design: the return value is deliberately ignored. */
    const ssize_t sent = sendto(s_sock, s_line, len, 0,
                                (struct sockaddr *)&s_target, sizeof(s_target));
    ESP_LOGD(TAG, "sent %d bytes: %d", len, (int)sent);
}

static void stats_task(void *arg)
{
    stats_snap_t last = {0};
    int64_t last_resolve_us = 0;
    vTaskDelay(pdMS_TO_TICKS(STATS_FIRST_DELAY_MS));
    for (;;) {
        stats_send_once(&last, &last_resolve_us);
        vTaskDelay(pdMS_TO_TICKS(CONFIG_SINKHOLE_STATS_INTERVAL_S * 1000));
    }
}

void stats_start(const char *node_ip)
{
    snprintf(s_node, sizeof(s_node), "%s", node_ip);
    /* Priority 2: below the updater (3) and far below the DNS task (5), so
     * stats can never starve serving. Not watchdog-subscribed (same as the
     * updater) — blocking in getaddrinfo here is harmless. */
    const BaseType_t ok = xTaskCreate(stats_task, "stats", 4096, NULL, 2, NULL);
    if (ok != pdPASS) {
        ESP_LOGW(TAG, "stats task not started"); /* serving is unaffected */
    }
}

#endif /* CONFIG_SINKHOLE_STATS_ENABLE */
