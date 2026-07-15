# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this project is

An ESP32-based DNS sinkhole (blocklist-based ad/tracker blocking, like a minimal
Pi-hole). It answers DNS queries on the LAN, returns NXDOMAIN for blocked
domains, and forwards everything else to an upstream resolver. Multiple identical
nodes run for redundancy. A separate offline build step turns public blocklists
into the binary the nodes consume.

**The single design priority is reliability.** This device is a network-critical
service — if it hangs, every client on the LAN loses DNS. Favor fewer moving
parts, static allocation, and fail-safe behavior over features, cleverness, or
performance. When in doubt, choose the more boring and more robust option.

## Hard constraints — do not violate

- **Ethernet only, no WiFi.** Two supported targets, both RMII: plain ESP32 +
  external LAN8720 (`idf.py set-target esp32`, the default), and ESP32-P4 +
  the Function-EV-Board's onboard IP101 (`idf.py set-target esp32p4`, pulls
  in `sdkconfig.defaults.esp32p4`). PHY driver and EMAC pin defaults are
  selected per-target — see `main/idf_component.yml`, `main/Kconfig.projbuild`,
  and the `CONFIG_IDF_TARGET_ESP32P4` branches in `main/dns_sinkhole.c`. Do not
  add WiFi code paths.
- **ESP-IDF v6.x**, not Arduino. Use ESP-IDF APIs (esp_eth, esp_netif,
  lwIP sockets, esp_task_wdt, esp_https_ota, NVS).
- **No per-query heap allocation.** The DNS request path must use pre-allocated
  static buffers only. Heap fragmentation kills long-running ESP32s. Avoid
  `malloc`/`free` and C++ `String`-like patterns in the hot loop.
- **PSRAM required** for the blocklist. Allocate the blocklist with
  `heap_caps_malloc(..., MALLOC_CAP_SPIRAM)`.
- **The DNS serve path must never block indefinitely.** Every socket has a
  timeout; the main loop must feed the task watchdog on every iteration,
  including timeouts and error paths.
- **Updates must never touch the serving path until fully validated.** Download
  and validate off to the side, then swap atomically. A bad or truncated update
  must leave the currently-served list untouched.
- **Never brick the node for a list change.** List updates go to a data
  partition, never via full-firmware OTA. Firmware OTA is reserved for code
  changes and must use dual OTA partitions with rollback-on-failure.

## Architecture

```
public blocklists (StevenBlack, OISD, AdGuard DNS filter, …)
        │
        ▼   [offline build step — Go, in generator/, runs on a server/Pi/NAS/CI, NOT the ESP]
   fetch → parse hosts/domain/ABP format → merge → dedupe → FNV-1a-64 hash → sort ascending → self-test
        │
        ├─► blocklist.bin      (sorted array of little-endian uint64 hashes, format 2)
        └─► manifest.json       {format, version, size, sha256, count, url}
        │
        ▼   [served directly by the generator's HTTP server, or copied to a static host]
   ESP nodes poll manifest on a timer → if version changed:
        verify format matches → download blob → inactive data slot →
        verify sha256 + size + MIN count
        → pass: record active slot in NVS, load into new PSRAM buffer,
                atomic pointer swap, free old buffer
        → fail: discard, keep serving previous list, retry next cycle
```

Key invariants:
- The **FNV-1a hash function must be byte-identical** between the firmware
  (`domain_hash` in `dns_sinkhole.c`, 64-bit) and the offline generator
  (`fnv1a64` in `generator/hash.go`). If you change one, change both, bump the
  manifest `format` field (currently 2) so a firmware/generator mismatch is
  refused rather than silently corrupting lookups, and update the pinned
  parity vectors in `generator/hash_test.go`.
- `blocklist.bin` is a flat, sorted-ascending array of `uint64_t` little-endian
  hashes (8 bytes/domain — PSRAM realistically caps this around ~250k domains).
  Lookup is binary search. Sorting is the generator's responsibility; the
  firmware may assert/verify sortedness on load but must not sort on-device.
- Blocked responses are **NXDOMAIN** (RCODE 3), not 0.0.0.0. Clients stop
  cleanly. Do not change this without being asked.
- Nodes are **stateless and identical.** Same blob + same manifest URL on every
  node. No coordinator. Redundancy is handled downstream by handing out multiple
  DNS servers via DHCP.

## Reliability guards that must exist

- **Task watchdog** on the DNS task, reset every loop iteration.
- **MIN_DOMAINS floor** enforced in *both* the generator (refuse to publish) and
  the on-device validator (refuse to swap). This is the most important guard:
  the common failure is a *successful* download of an empty/truncated list from a
  broken upstream, which the sha256 alone will not catch.
- **Upstream timeout** with silent drop on failure (client retries) — never
  block the loop waiting on a slow/dead upstream.
- **Dual data slots (A/B) + NVS active-slot record**, with boot-time fallback to
  the other slot if the active one fails to load/validate.

## Subdomain matching

Blocklists intend wildcard/subdomain semantics (blocking `example.com` should
block `ads.example.com`). Preferred approach: **left-drop matching** in the
lookup — hash the full name, then progressively drop leftmost labels and re-check
(`ads.example.com` → `example.com` → `com`), stopping at a small label floor.
This keeps the blob small. The alternative (expanding subdomains at build time)
bloats the blob and is not preferred. Confirm the current choice before changing
matching semantics.

## Build / flash

- `make build flash monitor` (plain ESP32), `make build-p4 flash-p4 monitor-p4`
  (ESP32-P4). Each target has its own build dir + sdkconfig (see `Makefile`)
  so building one never disturbs the other's config — don't run raw
  `idf.py set-target` at the repo root without `-B`/`-D SDKCONFIG=...`, or it
  clobbers whichever target's sdkconfig is currently checked out there.
- menuconfig must have: SPIRAM enabled; correct PHY (LAN8720 on ESP32, IP101 on
  ESP32-P4) and RMII pin assignment for the target board; a custom partition
  table with dual data partitions for the blocklist (+ dual OTA partitions if
  firmware OTA is added).
- Network access is available in this container for `idf.py`/component-manager
  fetches, but assume the human builds/flashes onto real hardware.

## What NOT to do

- Do not add query logging, DoH/DoT, per-client rules, or caching unless
  explicitly asked. The owner chose reliability over features. (The one
  sanctioned exception: the best-effort UDP stats reporting in `main/stats.c`
  + the generator's in-RAM `/stats` UI, added at the owner's request. It must
  stay fire-and-forget — never let it grow into something the serve path
  depends on.)
- Do not parse public blocklists on the ESP. That belongs in the offline build
  step.
- Do not introduce dynamic allocation into the query path.
- Do not add WiFi.
- Do not use full-firmware OTA to deliver list updates.

## Style

- C for firmware (ESP-IDF), Go for the offline generator (`generator/`).
- Keep functions small and readable; comment the *why*, especially around
  reliability trade-offs and the buffer/lifetime rules.
- Match the existing style in `dns_sinkhole.c` (static buffers, explicit sizes,
  clear separation between parse / lookup / respond / forward).
