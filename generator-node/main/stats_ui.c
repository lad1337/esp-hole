/* stats_ui.c — see stats_ui.h. */
#include "stats_ui.h"

#if CONFIG_GENERATOR_STATS_ENABLE

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

static const char *TAG = "stats_ui";

#define STATS_MAX_LINE  512
#define STATS_MAX_NODES 16 /* small fixed cap — a handful of sinkhole nodes in practice */
#define STATS_HIST_BUCKETS 16

typedef struct {
    bool used;
    char node[16]; /* dotted-quad IPv4, matches main/stats.c's node tag */
    uint32_t blocked, forwarded, timeouts, lat_sum_us; /* running sums of reported deltas */
    int64_t uptime_s;    /* gauge: latest value reported, not summed */
    int64_t last_seen_us;
    uint32_t hist[STATS_HIST_BUCKETS]; /* running sums */
} stats_node_t;

static stats_node_t s_nodes[STATS_MAX_NODES];

/* Finds node by exact string match, claiming a free slot on first sight.
 * ponytail: no eviction of stale nodes — a node cap this small (16) and a
 * handful of real sinkhole nodes means this never fills up in practice; add
 * LRU eviction if it ever does. */
static stats_node_t *find_or_create_node(const char *node, size_t len)
{
    if (len == 0 || len >= sizeof(s_nodes[0].node)) {
        return NULL;
    }
    stats_node_t *free_slot = NULL;
    for (int i = 0; i < STATS_MAX_NODES; i++) {
        if (s_nodes[i].used && strncmp(s_nodes[i].node, node, len) == 0 &&
            s_nodes[i].node[len] == '\0') {
            return &s_nodes[i];
        }
        if (!s_nodes[i].used && !free_slot) {
            free_slot = &s_nodes[i];
        }
    }
    if (free_slot) {
        memset(free_slot, 0, sizeof(*free_slot));
        memcpy(free_slot->node, node, len);
        free_slot->used = true;
    }
    return free_slot;
}

/* Parses one line of the exact subset main/stats.c emits:
 *   esphole,node=<ipv4> blocked=<n>i,forwarded=<n>i,...,h0=<n>i,...,h15=<n>i
 * Unknown fields ignored (forward compat); anything malformed is dropped —
 * this must never crash on garbage arriving on the socket. */
static void ingest_line(char *line, size_t len)
{
    const char *prefix = "esphole,node=";
    const size_t prefix_len = strlen(prefix);
    if (len <= prefix_len || strncmp(line, prefix, prefix_len) != 0) {
        return;
    }
    char *rest = line + prefix_len;
    char *space = memchr(rest, ' ', len - prefix_len);
    if (!space) {
        return;
    }
    *space = '\0';
    stats_node_t *n = find_or_create_node(rest, (size_t)(space - rest));
    if (!n) {
        return; /* not a valid node tag, or the node table is full */
    }
    n->last_seen_us = esp_timer_get_time();

    char *field = space + 1;
    while (field && *field) {
        char *comma = strchr(field, ',');
        if (comma) {
            *comma = '\0';
        }
        char *eq = strchr(field, '=');
        if (eq) {
            *eq = '\0';
            const char *key = field;
            const char *val = eq + 1;
            const long v = strtol(val, NULL, 10); /* trailing 'i' suffix just stops parsing early */
            if (strcmp(key, "blocked") == 0) {
                n->blocked += (uint32_t)v;
            } else if (strcmp(key, "forwarded") == 0) {
                n->forwarded += (uint32_t)v;
            } else if (strcmp(key, "timeouts") == 0) {
                n->timeouts += (uint32_t)v;
            } else if (strcmp(key, "lat_sum_us") == 0) {
                n->lat_sum_us += (uint32_t)v;
            } else if (strcmp(key, "uptime_s") == 0) {
                n->uptime_s = v; /* gauge, not summed */
            } else if (key[0] == 'h' && key[1] >= '0' && key[1] <= '9') {
                const int bucket = (int)strtol(key + 1, NULL, 10);
                if (bucket >= 0 && bucket < STATS_HIST_BUCKETS) {
                    n->hist[bucket] += (uint32_t)v;
                }
            }
        }
        field = comma ? comma + 1 : NULL;
    }
}

static void stats_listener_task(void *arg)
{
    (void)arg;
    static char buf[STATS_MAX_LINE];

    const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGW(TAG, "socket() failed, stats disabled for this boot");
        vTaskDelete(NULL);
        return;
    }
    const struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(CONFIG_GENERATOR_STATS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGW(TAG, "bind() failed, stats disabled for this boot");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "stats: listening on udp :%d", CONFIG_GENERATOR_STATS_PORT);

    for (;;) {
        const int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            continue; /* error or empty datagram — best-effort, just retry */
        }
        buf[n] = '\0';
        /* One datagram normally carries one line (main/stats.c never sends
         * more), but split on '\n' defensively anyway — cheap and matches
         * generator/stats.go's own tolerance for multi-line datagrams. */
        char *line = buf;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            const size_t line_len = nl ? (size_t)(nl - line) : strlen(line);
            if (line_len > 0) {
                ingest_line(line, line_len);
            }
            line = nl ? nl + 1 : NULL;
        }
    }
}

static esp_err_t stats_json_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *nodes = cJSON_AddArrayToObject(root, "nodes");
    const int64_t now = esp_timer_get_time();

    for (int i = 0; i < STATS_MAX_NODES; i++) {
        if (!s_nodes[i].used) {
            continue;
        }
        cJSON *n = cJSON_CreateObject();
        cJSON_AddStringToObject(n, "id", s_nodes[i].node);
        cJSON_AddNumberToObject(n, "blocked", s_nodes[i].blocked);
        cJSON_AddNumberToObject(n, "forwarded", s_nodes[i].forwarded);
        cJSON_AddNumberToObject(n, "timeouts", s_nodes[i].timeouts);
        cJSON_AddNumberToObject(n, "lat_sum_us", s_nodes[i].lat_sum_us);
        cJSON_AddNumberToObject(n, "uptime_s", (double)s_nodes[i].uptime_s);
        cJSON_AddNumberToObject(n, "last_seen_s",
                                (double)((now - s_nodes[i].last_seen_us) / 1000000));
        cJSON_AddItemToArray(nodes, n);
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        return httpd_resp_send_500(req);
    }
    httpd_resp_set_type(req, "application/json");
    const esp_err_t err = httpd_resp_sendstr(req, json);
    cJSON_free(json);
    return err;
}

/* Minimal static page: no charting library, just a table that polls /stats
 * every 5s. Full Go-generator-UI parity (per-minute history, uPlot charts)
 * would need embedding those JS/CSS assets and a time-series store — a much
 * bigger lift than "a stats ui" asked for; this is the lazy version. */
static const char STATS_HTML[] =
    "<!doctype html><html><head><meta charset=utf-8>"
    "<title>esp-hole stats</title><style>"
    "body{font-family:sans-serif;background:#111;color:#eee;padding:1rem}"
    "table{border-collapse:collapse;width:100%}"
    "td,th{padding:.4rem .8rem;border-bottom:1px solid #333;text-align:right}"
    "th:first-child,td:first-child{text-align:left}"
    "</style></head><body><h1>esp-hole node stats</h1>"
    "<table id=t><thead><tr><th>node</th><th>blocked</th><th>forwarded</th>"
    "<th>timeouts</th><th>avg latency</th><th>uptime</th><th>last seen</th>"
    "</tr></thead><tbody></tbody></table>"
    "<script>"
    "async function tick(){"
    "const r=await fetch('/stats');const d=await r.json();"
    "const tb=document.querySelector('#t tbody');tb.innerHTML='';"
    "for(const n of d.nodes){"
    "const avg=n.forwarded?Math.round(n.lat_sum_us/n.forwarded):0;"
    "const tr=document.createElement('tr');"
    "tr.innerHTML=`<td>${n.id}</td><td>${n.blocked}</td><td>${n.forwarded}</td>"
    "<td>${n.timeouts}</td><td>${avg} µs</td><td>${n.uptime_s}s</td>"
    "<td>${n.last_seen_s}s ago</td>`;"
    "tb.appendChild(tr);}}"
    "tick();setInterval(tick,5000);"
    "</script></body></html>";

static esp_err_t stats_ui_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_sendstr(req, STATS_HTML);
}

void stats_ui_start(httpd_handle_t server)
{
    const httpd_uri_t stats_uri = {
        .uri = "/stats",
        .method = HTTP_GET,
        .handler = stats_json_handler,
    };
    /* Registered both with and without the trailing slash — httpd's routing
     * is exact-match, and people/browsers type /stats/ui as often as
     * /stats/ui/. */
    const httpd_uri_t stats_ui_uri = {
        .uri = "/stats/ui/",
        .method = HTTP_GET,
        .handler = stats_ui_handler,
    };
    const httpd_uri_t stats_ui_uri_noslash = {
        .uri = "/stats/ui",
        .method = HTTP_GET,
        .handler = stats_ui_handler,
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &stats_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &stats_ui_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &stats_ui_uri_noslash));

    /* Low priority, matching main/stats.c's own sender task (prio 2) — well
     * below the refresh task (3) and httpd's default, so a flood of stats
     * traffic can never compete with fetch/generate/serve. */
    xTaskCreate(stats_listener_task, "stats_ui", 4096, NULL, 2, NULL);
}

#endif /* CONFIG_GENERATOR_STATS_ENABLE */
