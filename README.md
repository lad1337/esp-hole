# ESP-Hole

A minimal, reliability-first DNS sinkhole for the ESP32. It blocks ad and
tracker domains at the DNS level (like a stripped-down Pi-hole), returning
NXDOMAIN for blocked names and forwarding everything else to an upstream
resolver. Designed to run as one of several identical, redundant nodes on a LAN.

No WiFi, no web UI, no stats, no logging — just fast, dependable DNS filtering
that stays up.

## Design goals

- **Reliability above all.** This is network-critical infrastructure. If it
  hangs, the LAN loses DNS. Every design choice favors robustness over features.
- **Ethernet only** (LAN8720 / RMII). WiFi is deliberately excluded — a wired
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
4. **Not blocked** → forwards to the upstream resolver and relays the answer.
5. On failure/timeout it drops silently; the client retries. The loop never
   blocks, and a task watchdog resets the node if anything stalls.

The blocklist itself is not built on the ESP. A separate offline step turns
public blocklists into the binary the nodes consume.

## Architecture

```
Public blocklists (HaGeZi Pro by default; StevenBlack, OISD, …)
        │
        ▼   offline build step (Go — runs on a Pi / NAS / server / CI, in Docker)
   fetch → parse → merge → dedupe → FNV-1a-64 hash → sort → self-test
        │
        ├─► blocklist.bin   (sorted uint64 LE hashes, format 2)
        └─► manifest.json   {format, version, size, sha256, count, url}
        │
        ▼   served directly over HTTP by the generator (or copied to a static host)
   ESP nodes poll the manifest, and when the version changes:
        download → validate (format + sha256 + size + minimum count) → atomic swap
        (a bad/truncated update is rejected; the old list keeps serving)
```

Why the split: parsing multi-megabyte public lists on a microcontroller is
exactly the kind of fragile, memory-hungry work you don't want on a
reliability-critical device. The messy part happens upstream where there's real
CPU and RAM; the ESP only ever fetches a clean, fixed-format blob.

## Repository layout

| Path | What it is |
|------|------------|
| `main/dns_sinkhole.c` | Core firmware: Ethernet + UDP/53 serve loop, parse, lookup (left-drop), respond, forward. Reliability-focused (static buffers, watchdog, timeouts). |
| `main/blocklist.c/.h` | Dual-slot blocklist storage: PSRAM load with sha256/floor/sortedness validation, binary search, atomic swap, NVS active-slot record with boot fallback. |
| `main/updater.c/.h` | Self-update task: poll `manifest.json` → download to the inactive slot → validate → atomic swap. Failures keep the current list serving. |
| `generator/` | Go offline generator + HTTP server: public lists → `blocklist.bin` + `manifest.json`, served directly or written to disk (`-oneshot`). `go test ./...` covers hash vectors, parsing, self-test failure paths, and an end-to-end server test. |
| `generator/Dockerfile`, `docker-compose.yml` | Build/run the generator as a scratch-based container. |
| `partitions.csv` | 8 MB partition table with dual blocklist data slots (`blk_a`/`blk_b`). |
| `sdkconfig.defaults.esp32p4` | Overlay applied on top of `sdkconfig.defaults` when targeting ESP32-P4 (PSRAM speed for its memory interface). |
| `Makefile` | `make build`/`build-p4`, `flash`/`flash-p4`, `monitor`/`monitor-p4`, `menuconfig`/`menuconfig-p4` — each target uses its own build dir + sdkconfig so the two boards never clobber each other. Also wraps the Go generator/Docker commands. Run `make help` for the full list. |
| `CLAUDE.md` | Constraints and context for Claude Code. Read this before making changes. |

## Hardware

Two targets are supported, both RMII, no WiFi antenna needed either way:

- **Plain ESP32 with PSRAM** (e.g. ESP32-WROVER) + an external **LAN8720**
  PHY. Wire per your board and set the RMII pins in menuconfig.
- **ESP32-P4-Function-EV-Board** — uses its onboard **IP101** PHY. Pin
  defaults (MDC/MDIO/reset + the RMII data lines) already match this board
  out of the box.

## Building

Requires [ESP-IDF v6.x](https://docs.espressif.com/projects/esp-idf/) sourced
in your shell (`source ~/.espressif/tools/activate_idf_v6.0.2.sh` if you
installed it via EIM, per `eim_config.toml`).

```bash
make build       # plain ESP32 + external LAN8720 → build/, sdkconfig
make build-p4    # ESP32-P4-Function-EV-Board       → build.esp32p4/, sdkconfig.esp32p4
make flash       # or flash-p4 — PORT=/dev/tty... to override auto-detection
make monitor     # or monitor-p4
make menuconfig  # or menuconfig-p4 — "DNS sinkhole" menu: RMII pins/PHY
                 # address, if your board differs from the target's defaults
```

`make help` lists every target, including the Go generator/Docker wrappers.
Each target uses its own build directory and `sdkconfig` file (see
`Makefile`), so switching between the two boards never clobbers the other's
configuration. Equivalent raw `idf.py` commands still work if you prefer
them directly:

```bash
idf.py set-target esp32       # or: idf.py set-target esp32p4
idf.py menuconfig
idf.py build flash monitor
```

SPIRAM, the PHY driver (LAN8720 on ESP32 / IP101 on ESP32-P4, selected
automatically per target), and the dual-slot partition table are already set
up by `sdkconfig.defaults` (+ `sdkconfig.defaults.esp32p4` on P4) /
`partitions.csv` (sized for 8 MB flash — see the comment in `partitions.csv`
for the 4 MB variant; the P4 board's 16 MB flash also fits this table with
room to spare).

## Generating and publishing the blocklist

The generator (`generator/`, Go) both builds the blocklist and serves it —
there's no separate "upload to a static host" step, though you can still copy
the files out of its data dir if you'd rather host them elsewhere.

Copy `generator/config.example.json` to `generator/config.json` and edit
`sources` / `public_url_base` for your setup, then either:

```bash
docker compose up -d --build     # long-running: serves manifest.json + blocklist.bin,
                                  # refreshes from sources on a timer
```

or, for a one-off local run:

```bash
cd generator
go run . -config config.json -oneshot   # writes to data_dir and exits
```

A cached copy for offline testing lives at `cache/hagezi-pro.txt` (point a
`sources` entry at that local path). Set `MANIFEST_URL` in `main/updater.c` to
`public_url_base + "/manifest.json"`.

The generator refuses to publish fewer than `min_domains` (default 10000) so a
broken upstream can never ship an empty list; the firmware enforces the same
floor (`BLOCKLIST_MIN_DOMAINS`) before swapping, and also checks the
manifest's `format` field so a node can never load a blob hashed with a
different scheme. Every generation is self-tested (manifest consistency,
sha256, sortedness, and a full lookup round-trip of every input domain)
before it's published or written to disk — a failed self-test changes
nothing, and the server keeps serving whatever it last published. Run
`go test ./...` in `generator/` to exercise all of this offline.

## Configuration

Edit the defines at the top of `main/dns_sinkhole.c`:

| Define | Meaning |
|--------|---------|
| `UPSTREAM_IP` | Upstream resolver (e.g. `1.1.1.1`, `9.9.9.9`). |
| `UPSTREAM_TIMEOUT_MS` | How long to wait for upstream before dropping. |
| `WDT_TIMEOUT_S` | Task watchdog timeout. |

And at the top of `main/updater.c`:

| Define | Meaning |
|--------|---------|
| `MANIFEST_URL` | Where the nodes poll for `manifest.json` (**must be edited**). |
| `UPDATE_POLL_S` | How often to check the manifest (default hourly). |

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
- [x] Offline blocklist generator + server (`generator/`, Go) → `blocklist.bin` + `manifest.json`, uint64 FNV-1a (format 2)
- [x] On-device self-update (poll manifest → validate → atomic swap, dual slots + NVS)
- [x] Subdomain matching (left-drop lookup)
- [x] Firmware builds clean against ESP-IDF v6.0.2 for both ESP32 and ESP32-P4
- [ ] Firmware OTA (dual OTA partitions + rollback) — for *code* updates only
- [ ] Verified on hardware (`idf.py build flash monitor` — builds clean in this dev container, no hardware attached)

## Non-goals

Query logging, statistics, web UI, DoH/DoT, per-client rules, and caching are
intentionally out of scope. This is a reliability-first blocker, not a
feature-complete AdGuard Home replacement. For that experience, a Pi or OpenWrt
router is the better substrate.
