# ESP-Hole

A minimal, reliability-first DNS sinkhole for the ESP32. It blocks ad and
tracker domains at the DNS level (like a stripped-down Pi-hole), returning
NXDOMAIN for blocked names and forwarding everything else to an upstream
resolver. Designed to run as one of several identical, redundant nodes on a LAN.

No WiFi, no per-client rules, no query logging — just fast, dependable DNS
filtering that stays up. (Best-effort node stats and a small answer cache are
sanctioned exceptions, added at the owner's request — see below. Neither can
affect the serve path if it fails.)

Two firmware roles live in this repo: the **DNS-sinkhole** (`main/`, the
LAN-facing nodes that answer queries) and the **generator**
(`generator-node/`, a dedicated ESP32-P4 firmware that builds the blocklist
those nodes consume — no laptop/server/Docker host needed). See
`CLAUDE.md`'s "Firmware roles" section for the full reasoning.

## Design goals

- **Reliability above all.** This is network-critical infrastructure. If it
  hangs, the LAN loses DNS. Every design choice favors robustness over features.
- **Ethernet only** (RMII). WiFi is deliberately excluded — a wired
  always-on network service is far more dependable.
- **Redundant by default.** Run two or more identical nodes; hand out multiple
  DNS servers via DHCP so clients fail over automatically.
- **Small footprint.** The blocklist is stored as sorted 64-bit hashes in PSRAM
  — 8 bytes/domain, so a ~250k-domain list is ~2 MB, searched in ~18 comparisons.

## How it works

1. The node listens on UDP/53.
2. For each query it parses the domain, hashes it (FNV-1a), and binary-searches
   the in-PSRAM sorted blocklist.
3. **Blocked** → replies NXDOMAIN. Clients stop cleanly.
4. **Not blocked** → checks a small local answer cache (100 entries, flat 5 min
   TTL, static array — no heap) keyed on domain + query type; on a miss,
   forwards to the upstream resolver, relays the answer, and caches it.
5. On failure/timeout it drops silently; the client retries. The loop never
   blocks, and a task watchdog resets the node if anything stalls.

The blocklist isn't built on the *sinkhole* nodes themselves — a separate
device turns public blocklists into the binary they consume. That "separate
device" is `generator-node/`: another ESP32-P4, running a different firmware
role, not the sinkhole nodes doing double duty.

## Architecture

```
Public blocklists (StevenBlack, OISD, AdGuard DNS filter, …)
        │
        ▼   generator-node/ — its own ESP32-P4 firmware, own project/partition table
   fetch → parse → merge/dedupe → FNV-1a-64 hash → sort → self-test
        │
        ├─► blocklist.bin   (sorted uint64 LE hashes, format 2)
        └─► manifest.json   {format, version, size, sha256, count, url}
        │
        ▼   served directly over HTTP by the generator node
   DNS-sinkhole nodes poll the manifest, and when the version changes:
        download → validate (format + sha256 + size + minimum count) → atomic swap
        (a bad/truncated update is rejected; the old list keeps serving)
```

Why the split: parsing multi-megabyte public lists is exactly the kind of
fragile, memory-hungry work you don't want on a reliability-critical
DNS-serving device. The messy part happens on a dedicated generator node; the
sinkhole nodes only ever fetch a clean, fixed-format blob — same reasoning as
running a separate build server, just without needing one: the whole fleet
is ESP32-P4 hardware, no laptop/server/Docker dependency anywhere.

## Repository layout

| Path | What it is |
|------|------------|
| `main/dns_sinkhole.c` | Core firmware: Ethernet + UDP/53 serve loop, parse, lookup (left-drop), 100-entry LRU answer cache, respond, forward. Reliability-focused (static buffers, watchdog, timeouts). |
| `main/blocklist.c/.h` | Dual-slot blocklist storage: PSRAM load with sha256/floor/sortedness validation, binary search, atomic swap, NVS active-slot record with boot fallback. |
| `main/updater.c/.h` | Self-update task: poll `manifest.json` → download to the inactive slot → validate → atomic swap. Failures keep the current list serving. |
| `main/stats.c/.h` | Best-effort UDP node-stats reporting (query counts, latency histogram) — fire-and-forget, never affects serving. |
| `generator-node/` | The generator role: its own ESP32-P4 ESP-IDF firmware/project — fetch/parse/dedupe/hash/sort/self-test the public lists, persist across reboot, serve `manifest.json`/`blocklist.bin`. See "Generator node" below. |
| `generator-node/components/blocklist_pipeline/` | Portable core (parse/normalize/hash/dedupe/sort/self-test) — zero ESP-IDF headers, host-testable with plain `cc` (`test/`), no hardware needed. |
| `partitions.csv` | 32 MB partition table with dual blocklist data slots (`blk_a`/`blk_b`). |
| `sdkconfig.defaults` | Board defaults for the ESP32-P4-Function-EV-Board (PSRAM speed, flash size, partition table). |
| `Makefile` | `make build`/`flash`/`monitor`/`menuconfig` (sinkhole) and `make build-gen`/`flash-gen`/etc. (generator-node), plus `make ports`. Run `make help` for the full list. |
| `CLAUDE.md` | Constraints and context for Claude Code. Read this before making changes. |

## Hardware

**ESP32-P4-Function-EV-Board** — uses its onboard **IP101** RMII PHY. Pin
defaults (MDC/MDIO/reset + the RMII data lines) already match this board out
of the box; no WiFi antenna needed.

## Building

Requires [ESP-IDF v6.x](https://docs.espressif.com/projects/esp-idf/) sourced
in your shell (`source ~/.espressif/tools/activate_idf_v6.0.2.sh` if you
installed it via EIM, per `eim_config.toml`).

```bash
make ports       # list connected USB serial ports (helps when two boards are attached)

make build       # sinkhole firmware → build/, sdkconfig
make flash       # PORT=/dev/tty... to override auto-detection
make monitor
make menuconfig  # "DNS sinkhole" menu: RMII pins/PHY address, if your board
                 # differs from the defaults

make build-gen   # generator-node firmware → generator-node/build/, generator-node/sdkconfig
make flash-gen   # PORT=/dev/tty... to override auto-detection
make monitor-gen
make menuconfig-gen  # "Generator node" menu: source URLs, refresh interval,
                     # HTTP port, allowlist, stats — see "Generator node" below
```

`make help` lists every target. An equivalent raw `idf.py` sequence still
works if you prefer it directly (from the repo root for the sinkhole, from
`generator-node/` for the generator):

```bash
idf.py set-target esp32p4
idf.py menuconfig
idf.py build flash monitor
```

SPIRAM, the IP101 PHY driver, and the dual-slot partition table are already
set up by `sdkconfig.defaults` / `partitions.csv` (sized for the board's
32 MB flash) — same for `generator-node/sdkconfig.defaults` and
`generator-node/partitions.csv`.

Both projects support a gitignored `sdkconfig.local` (`generator-node/sdkconfig.local`
for the generator) layered on top of `sdkconfig.defaults` for machine-specific
overrides — e.g. `CONFIG_SINKHOLE_MANIFEST_URL` pointed at your generator
node's LAN IP, or `CONFIG_GENERATOR_ALLOWLIST` with your own domains — without
committing them. It survives `fullclean`/`set-target` regenerating `sdkconfig`.

## Generator node

`generator-node/` is its own ESP32-P4 firmware: flash it to a dedicated
board and it fetches the configured public blocklists over HTTPS, merges/
dedupes/hashes/sorts them, self-tests the result, persists it across its own
reboot, and serves it — no laptop, server, or Docker host involved.

```bash
make build-gen flash-gen        # flash a dedicated board
make menuconfig-gen             # "Generator node" menu — see options below
```

On boot it restores whatever it last published (if anything) so
`/manifest.json`/`/blocklist.bin` answer immediately, then runs its first
fetch+generate cycle a few seconds later and every `GENERATOR_REFRESH_INTERVAL_S`
after that (default 6h). A dead/unreachable source is logged and skipped —
only the aggregate domain-count floor gates whether a generation publishes.

**Kconfig options** (`menuconfig-gen`, or `generator-node/sdkconfig.local`):

| Option | Meaning |
|--------|---------|
| `GENERATOR_SOURCE_URL_1/2/3` | Blocklist source URLs (empty slot = disabled). |
| `GENERATOR_MIN_DOMAINS` | Refuse-to-publish floor — must match `BLOCKLIST_MIN_DOMAINS` in `main/blocklist.h`. |
| `GENERATOR_REFRESH_INTERVAL_S` | How often to re-fetch and regenerate (default 21600 = 6h). |
| `GENERATOR_HTTP_PORT` | HTTP port (default 80). |
| `GENERATOR_PUBLIC_URL_BASE` | Address sinkhole nodes reach this node at; empty = use its own detected IP. |
| `GENERATOR_ALLOWLIST` | Comma-separated domains that are never blocked (up to 32), filtered out before publish — for a false positive on a public source. |
| `GENERATOR_STATS_ENABLE` / `GENERATOR_STATS_PORT` | UDP node-stats collector (see "Configuration" below) — default on, port 8094. |

**HTTP endpoints:**

| Route | What it does |
|-------|--------------|
| `GET /manifest.json`, `GET /blocklist.bin` | What sinkhole nodes poll/download. 503 until the first publish. |
| `GET /healthz` | `200 ok`. |
| `GET /refresh` | Triggers a fetch+generate cycle immediately instead of waiting out the interval. Returns right away; the cycle itself runs in the background. |
| `GET /stats`, `GET /stats/ui/` | Node query stats — see "Configuration" below. |

Every generation is self-tested (manifest consistency, sha256, strict
ascending order, and a full lookup round-trip of every input domain) before
it's published or persisted — a failed self-test changes nothing, and the
node keeps serving whatever it last published. The portable core
(`generator-node/components/blocklist_pipeline/`) is host-testable with
plain `cc`, no hardware or ESP-IDF needed:

```bash
make -C generator-node/components/blocklist_pipeline/test        # fast, offline
make -C generator-node/components/blocklist_pipeline/test scale-test  # real sources, timing/memory numbers
```

## Configuration

**DNS-sinkhole** (`main/dns_sinkhole.c`) — edit the defines at the top:

| Define | Meaning |
|--------|---------|
| `UPSTREAM_IP` | Upstream resolver (e.g. `1.1.1.1`, `9.9.9.9`). |
| `UPSTREAM_TIMEOUT_MS` | How long to wait for upstream before dropping. |
| `WDT_TIMEOUT_S` | Task watchdog timeout. |
| `DNS_CACHE_SIZE` / `DNS_CACHE_TTL_US` | Answer cache size (default 100 entries) and flat TTL (default 5 min). |

**DNS-sinkhole Kconfig options** (`menuconfig`, or `sdkconfig.local`):

| Option | Meaning |
|--------|---------|
| `SINKHOLE_MANIFEST_URL` | Where this node polls for `manifest.json` (**must be edited** — point it at your generator node). |
| `SINKHOLE_STATS_ENABLE` / `SINKHOLE_STATS_HOST` / `SINKHOLE_STATS_PORT` | Best-effort UDP query stats reporting — point `SINKHOLE_STATS_HOST` at your generator node's IP and `SINKHOLE_STATS_PORT` at its `GENERATOR_STATS_PORT` to feed `/stats`. |

`main/updater.c` polls `SINKHOLE_MANIFEST_URL` hourly by default
(`UPDATE_POLL_S`).

**Tip for redundancy:** give different nodes different upstreams (one on
`1.1.1.1`, another on `9.9.9.9`) so a single upstream outage doesn't degrade
every node identically. Flash the *same* `blocklist.bin` to all nodes so answers
are consistent.

## Deploying multiple nodes

1. Flash the same firmware + same blocklist to each node.
2. Give each a static IP (or a DHCP reservation).
3. In your DHCP server, hand out two or more DNS servers pointing at the nodes.
4. Optionally set a secondary DNS pointing straight at an upstream resolver, so
   a total sinkhole failure degrades to "ads get through" rather than "internet
   is down."

Clients fail over on timeout automatically. Note that OS DNS-server selection
isn't evenly load-balanced — this gives redundancy, not perfect balancing, which
is fine here.

## Blocked-response behavior

Blocked domains return **NXDOMAIN**, not `0.0.0.0`. Clients treat it as "no such
host" and stop, which is cleaner than pointing them at a dead IP. Change
`make_nxdomain` if you want a 0.0.0.0 A-record instead.

## Status / roadmap

- [x] Core serve loop (parse / lookup / respond / forward) with reliability guards
- [x] 100-entry LRU answer cache (flat 5 min TTL, keyed on domain + query type)
- [x] Generator node (`generator-node/`) — dedicated ESP32-P4 firmware: fetch →
      parse → dedupe → hash → sort → self-test → persist → serve, no
      laptop/server dependency
- [x] On-device self-update (poll manifest → validate → atomic swap, dual slots + NVS)
- [x] Subdomain matching (left-drop lookup)
- [x] Best-effort node query stats (UDP report + `/stats` UI on the generator node)
- [x] Manual allowlist on the generator (never-block domains, filtered before publish)
- [x] Verified end-to-end on real hardware: two physical ESP32-P4 boards, one
      generator + one sinkhole, unmodified sinkhole firmware consuming a
      blocklist produced entirely by the generator node
- [ ] Firmware OTA (dual OTA partitions + rollback) — for *code* updates only

## Non-goals

Full query logging, DoH/DoT, per-client rules, and a general caching layer
(beyond the small fixed answer cache above) are intentionally out of scope.
This is a reliability-first blocker, not a feature-complete AdGuard Home
replacement. For that experience, a Pi or OpenWrt router is the better
substrate. (Best-effort node stats and the answer cache are the two
sanctioned exceptions — see `CLAUDE.md`.)
