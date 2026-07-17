/* dns_sinkhole.c — ESP32 DNS sinkhole: Ethernet bring-up + UDP/53 serve loop.
 *
 * Serve path per query: parse → lookup → respond (NXDOMAIN) | forward.
 *
 * Reliability rules (see CLAUDE.md):
 *  - no heap allocation anywhere in the serve path: all buffers are static,
 *  - every socket has a timeout; nothing here can block indefinitely,
 *  - the task watchdog is fed on every loop iteration, including timeout and
 *    error paths, and panics (→ reboot) if the loop ever stalls,
 *  - failures are silent drops: the client's own retry is the recovery path.
 */
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_eth.h"
#include "esp_eth_netif_glue.h"
#include "esp_eth_phy_ip101.h" /* onboard PHY on the ESP32-P4-Function-EV-Board */
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "nvs_flash.h"

#include "blocklist.h"
#include "stats.h"
#include "updater.h"

/* ---- configuration ------------------------------------------------------ */
#define UPSTREAM_IP         "1.1.1.1" /* tip: give each node a different upstream */
#define UPSTREAM_TIMEOUT_MS 1500      /* wait this long for upstream, then drop */
#define WDT_TIMEOUT_S       10        /* task watchdog: panic + reboot on stall */
/* ------------------------------------------------------------------------- */

#define DNS_PORT    53
#define DNS_MAX_PKT 1500 /* one MTU; larger UDP answers are vanishingly rare */
#define DNS_MAX_NAME 254 /* 253 chars dotted form + NUL */

#define DNS_CACHE_SIZE  100
#define DNS_CACHE_TTL_US (5LL * 60 * 1000000) /* 5 min, flat — not the answer's own TTL */

static const char *TAG = "sinkhole";

/* Static buffers — the serve path never allocates. Single DNS task, so no
 * sharing hazards. s_pkt holds the request and is patched in place for
 * NXDOMAIN replies; s_ans holds the relayed upstream answer. */
static uint8_t s_pkt[DNS_MAX_PKT];
static uint8_t s_ans[DNS_MAX_PKT];
static char s_name[DNS_MAX_NAME];

/* Upstream-answer cache for non-blocked queries — 100 entries, flat 5 min
 * TTL, LRU eviction. Static array, no heap: DNS_CACHE_SIZE * DNS_MAX_PKT is
 * ~150 KiB of internal RAM, comfortably inside what's free (this is not
 * PSRAM — the blocklist owns that). Key is domain_hash(name) combined with
 * the query TYPE (A vs AAAA are different answers for the same name) — a
 * plain per-name cache would serve an A-record cache hit to an AAAA query.
 * O(n) scan on every lookup/insert; n=100 makes that irrelevant next to a
 * real UDP round-trip. */
typedef struct {
    bool valid;
    uint64_t key;
    int64_t inserted_us;
    uint32_t last_used; /* LRU clock tick; lowest = evict first */
    uint16_t len;
    uint8_t data[DNS_MAX_PKT];
} dns_cache_entry_t;

static dns_cache_entry_t s_cache[DNS_CACHE_SIZE];
static uint32_t s_cache_clock;

static EventGroupHandle_t s_net_events;
#define GOT_IP_BIT BIT0
static char s_node_ip[16];           /* dotted-quad, filled in on_got_ip() */

/* 64-bit FNV-1a. Must stay byte-identical to fnv1a64() in the offline
 * generator (generator/hash.go) — if you change one, change both and bump
 * the manifest format. 64 bits puts the false-positive odds of an unlisted
 * domain colliding with a blocked one at ~10^-14 per lookup. */
static uint64_t domain_hash(const char *s, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* Returns the cache slot for key, or -1 on a miss (not found, or found but
 * past DNS_CACHE_TTL_US — expired entries are invalidated in place so the
 * slot is immediately reusable). */
static int dns_cache_find(uint64_t key, int64_t now)
{
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (s_cache[i].valid && s_cache[i].key == key) {
            if (now - s_cache[i].inserted_us > DNS_CACHE_TTL_US) {
                s_cache[i].valid = false;
                return -1;
            }
            s_cache[i].last_used = ++s_cache_clock;
            return i;
        }
    }
    return -1;
}

/* Inserts/overwrites the entry for key, evicting a free slot if one exists,
 * else the least-recently-used one. Silently drops (never truncates) an
 * answer too large for the buffer — vanishingly rare, and a cache miss next
 * time is harmless. */
static void dns_cache_insert(uint64_t key, const uint8_t *data, int len, int64_t now)
{
    if (len <= 0 || (size_t)len > sizeof(s_cache[0].data)) {
        return;
    }
    int victim = 0;
    uint32_t oldest = UINT32_MAX;
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!s_cache[i].valid) {
            victim = i;
            break;
        }
        if (s_cache[i].last_used < oldest) {
            oldest = s_cache[i].last_used;
            victim = i;
        }
    }
    dns_cache_entry_t *e = &s_cache[victim];
    e->valid = true;
    e->key = key;
    e->inserted_us = now;
    e->last_used = ++s_cache_clock;
    e->len = (uint16_t)len;
    memcpy(e->data, data, (size_t)len);
}

/* Extract the first question name as a dotted, lowercased string (no trailing
 * dot). Returns the offset just past the question (qname + qtype + qclass),
 * or -1 on anything malformed. Compression pointers are invalid in a query
 * qname, so any pointer byte is treated as malformed. */
static int parse_question(const uint8_t *pkt, int len, char *name, size_t name_sz)
{
    if (len < 12) {
        return -1;
    }
    if (pkt[2] & 0x80) {
        return -1; /* QR set: a response, not a query */
    }
    const int qdcount = (pkt[4] << 8) | pkt[5];
    if (qdcount < 1) {
        return -1;
    }

    int off = 12;
    size_t n = 0;
    for (;;) {
        if (off >= len) {
            return -1;
        }
        const uint8_t lab = pkt[off++];
        if (lab == 0) {
            break;
        }
        if ((lab & 0xC0) != 0 || off + lab > len) {
            return -1;
        }
        if (n + lab + (n ? 1 : 0) >= name_sz) {
            return -1;
        }
        if (n) {
            name[n++] = '.';
        }
        for (int i = 0; i < lab; i++) {
            const char c = (char)pkt[off + i];
            name[n++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        off += lab;
    }
    name[n] = '\0';

    if (off + 4 > len) {
        return -1; /* qtype + qclass must follow */
    }
    return off + 4;
}

/* Left-drop subdomain matching: check the full name, then progressively drop
 * leftmost labels (ads.example.com → example.com), stopping at a two-label
 * floor so a stray "com" in a source list can never blackhole a whole TLD. */
static bool is_blocked(const char *name)
{
    if (name[0] == '\0') {
        return false;
    }
    int labels = 1;
    for (const char *q = name; *q; q++) {
        if (*q == '.') {
            labels++;
        }
    }
    const char *p = name;
    for (;;) {
        if (blocklist_contains(domain_hash(p, strlen(p)))) {
            return true;
        }
        if (labels <= 2) {
            return false;
        }
        p = strchr(p, '.') + 1;
        labels--;
    }
}

/* Patch the request in place into an NXDOMAIN response (RCODE 3, not
 * 0.0.0.0 — clients treat it as "no such host" and stop cleanly). Echoes
 * the question; drops any additional records (EDNS OPT included). */
static int make_nxdomain(uint8_t *pkt, int q_end)
{
    pkt[2] = 0x80 | (pkt[2] & 0x79); /* QR=1, keep opcode + RD, clear AA/TC */
    pkt[3] = 0x83;                   /* RA=1, RCODE=3 (NXDOMAIN) */
    pkt[4] = 0;
    pkt[5] = 1;                      /* QDCOUNT=1 */
    memset(pkt + 6, 0, 6);           /* ANCOUNT/NSCOUNT/ARCOUNT = 0 */
    return q_end;
}

/* Send the query upstream and wait (bounded) for the matching answer.
 * Returns the answer length, or -1 on timeout/error — the caller drops
 * silently and the client retries. */
static int forward_upstream(int usock, const uint8_t *query, int qlen,
                            uint8_t *ans, size_t ans_sz)
{
    if (send(usock, query, qlen, 0) != qlen) {
        return -1;
    }
    /* Drain stale answers from earlier timed-out queries until the ID
     * matches. Bounded iterations so this can never outlast the watchdog
     * even if garbage keeps arriving. */
    for (int tries = 0; tries < 4; tries++) {
        const int n = recv(usock, ans, ans_sz, 0);
        if (n < 0) {
            return -1; /* SO_RCVTIMEO expired or socket error */
        }
        if (n >= 12 && ans[0] == query[0] && ans[1] == query[1] &&
            (ans[2] & 0x80)) {
            return n;
        }
    }
    return -1;
}

/* Create + bind a socket, retrying forever — the node is useless without it,
 * and transient lwIP states must not kill the serve task. */
static int make_socket_retry(const struct sockaddr_in *bind_addr,
                             const struct sockaddr_in *connect_addr,
                             int rcv_timeout_ms)
{
    for (;;) {
        const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock >= 0) {
            const struct timeval tv = {
                .tv_sec = rcv_timeout_ms / 1000,
                .tv_usec = (rcv_timeout_ms % 1000) * 1000,
            };
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (bind_addr == NULL ||
                bind(sock, (const struct sockaddr *)bind_addr,
                     sizeof(*bind_addr)) == 0) {
                if (connect_addr == NULL ||
                    connect(sock, (const struct sockaddr *)connect_addr,
                            sizeof(*connect_addr)) == 0) {
                    return sock;
                }
            }
            close(sock);
        }
        ESP_LOGE(TAG, "socket setup failed (errno %d), retrying", errno);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

static void dns_task(void *arg)
{
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));

    const struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    struct sockaddr_in upstream_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
    };
    inet_pton(AF_INET, UPSTREAM_IP, &upstream_addr.sin_addr);

    /* Listen socket: 1 s receive timeout so the loop (and the watchdog feed)
     * always turns over, even on an idle network. */
    const int sock = make_socket_retry(&listen_addr, NULL, 1000);
    const int usock = make_socket_retry(NULL, &upstream_addr, UPSTREAM_TIMEOUT_MS);

    ESP_LOGI(TAG, "serving on UDP/%d, upstream %s, %u domains blocked",
             DNS_PORT, UPSTREAM_IP, (unsigned)blocklist_count());

    for (;;) {
        /* Fed on every path: idle timeout, malformed packet, upstream
         * timeout, success. Worst-case iteration (upstream wait + drains)
         * stays well under WDT_TIMEOUT_S. */
        esp_task_wdt_reset();

        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        const int n = recvfrom(sock, s_pkt, sizeof(s_pkt), 0,
                               (struct sockaddr *)&client, &client_len);
        if (n < 0) {
            continue; /* receive timeout — loop to feed the watchdog */
        }

        const int q_end = parse_question(s_pkt, n, s_name, sizeof(s_name));
        if (q_end < 0) {
            continue; /* malformed: drop silently */
        }

        if (is_blocked(s_name)) {
            stats_count_blocked();
            const int rlen = make_nxdomain(s_pkt, q_end);
            sendto(sock, s_pkt, rlen, 0, (struct sockaddr *)&client, client_len);
        } else {
            /* Cache key includes qtype: A and AAAA are different answers for
             * the same name, and a name-only key would serve one for the
             * other. qtype sits at the 2 bytes right before qclass, i.e.
             * right before q_end (parse_question's returned offset is just
             * past qtype+qclass). */
            const uint16_t qtype = ((uint16_t)s_pkt[q_end - 4] << 8) | s_pkt[q_end - 3];
            const uint64_t cache_key =
                domain_hash(s_name, strlen(s_name)) ^ ((uint64_t)qtype << 32);
            const int64_t now = esp_timer_get_time();
            const int hit = dns_cache_find(cache_key, now);

            if (hit >= 0) {
                /* Replay the cached answer bytes with this query's own
                 * transaction ID patched in — clients drop a response whose
                 * ID doesn't match their query. */
                memcpy(s_ans, s_cache[hit].data, s_cache[hit].len);
                s_ans[0] = s_pkt[0];
                s_ans[1] = s_pkt[1];
                stats_count_forwarded(0); /* ponytail: counted as forwarded, not a separate cache-hit stat */
                sendto(sock, s_ans, s_cache[hit].len, 0, (struct sockaddr *)&client,
                       client_len);
            } else {
                const int64_t t0 = now;
                const int alen = forward_upstream(usock, s_pkt, n, s_ans, sizeof(s_ans));
                if (alen > 0) {
                    stats_count_forwarded((uint32_t)(esp_timer_get_time() - t0));
                    dns_cache_insert(cache_key, s_ans, alen, now);
                    sendto(sock, s_ans, alen, 0, (struct sockaddr *)&client,
                           client_len);
                } else {
                    /* upstream slow/dead — drop silently, client retries */
                    stats_count_timeout();
                }
            }
        }
    }
}

static void on_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    const ip_event_got_ip_t *event = data;
    ESP_LOGI(TAG, "got IP " IPSTR, IP2STR(&event->ip_info.ip));
    snprintf(s_node_ip, sizeof(s_node_ip), IPSTR, IP2STR(&event->ip_info.ip));
    xEventGroupSetBits(s_net_events, GOT_IP_BIT);
}

static void eth_start(void)
{
#if CONFIG_SINKHOLE_ETH_PHY_POWER_GPIO >= 0
    /* Some boards gate the PHY power / 50 MHz oscillator behind a GPIO. */
    const gpio_config_t power_pin = {
        .pin_bit_mask = 1ULL << CONFIG_SINKHOLE_ETH_PHY_POWER_GPIO,
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&power_pin));
    gpio_set_level(CONFIG_SINKHOLE_ETH_PHY_POWER_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(50)); /* let the PHY/oscillator settle */
#endif

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    const esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 3, 0)
    emac_config.smi_gpio.mdc_num = CONFIG_SINKHOLE_ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = CONFIG_SINKHOLE_ETH_MDIO_GPIO;
#else
    emac_config.smi_mdc_gpio_num = CONFIG_SINKHOLE_ETH_MDC_GPIO;
    emac_config.smi_mdio_gpio_num = CONFIG_SINKHOLE_ETH_MDIO_GPIO;
#endif
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = CONFIG_SINKHOLE_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = CONFIG_SINKHOLE_ETH_PHY_RST_GPIO;
    esp_eth_phy_t *phy = esp_eth_phy_new_ip101(&phy_config);

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif,
                                     esp_eth_new_netif_glue(eth_handle)));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                               on_got_ip, NULL));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
}

void app_main(void)
{
    /* Compile-time config, printed at boot to make it obvious that a
     * `make flash` after an sdkconfig.local change actually took effect. */
    ESP_LOGI(TAG, "config: manifest_url=%s stats_host=%s",
             CONFIG_SINKHOLE_MANIFEST_URL, CONFIG_SINKHOLE_STATS_HOST);

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(err);
    }

    /* Widen the task watchdog before the DNS task subscribes to it. */
    const esp_task_wdt_config_t wdt_cfg = {
        .timeout_ms = WDT_TIMEOUT_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    if (esp_task_wdt_reconfigure(&wdt_cfg) != ESP_OK) {
        ESP_ERROR_CHECK(esp_task_wdt_init(&wdt_cfg));
    }

    if (blocklist_init() != ESP_OK) {
        /* Fail-safe: unfiltered DNS beats no DNS. The updater will fetch a
         * good list; until then everything is forwarded. */
        ESP_LOGW(TAG, "no valid blocklist in either slot — serving unfiltered");
    }

    s_net_events = xEventGroupCreate();
    configASSERT(s_net_events != NULL);
    eth_start();
    ESP_LOGI(TAG, "waiting for Ethernet...");
    xEventGroupWaitBits(s_net_events, GOT_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    const BaseType_t ok =
        xTaskCreate(dns_task, "dns", 6144, NULL, 5, NULL);
    configASSERT(ok == pdPASS);
    updater_start();
    stats_start(s_node_ip);
}
