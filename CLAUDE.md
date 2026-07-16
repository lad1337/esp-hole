# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this project is

An ESP32-based DNS sinkhole (blocklist-based ad/tracker blocking, like a minimal
Pi-hole). It answers DNS queries on the LAN, returns NXDOMAIN for blocked
domains, and forwards everything else to an upstream resolver. Multiple identical
nodes run for redundancy. A separate build step turns public blocklists into the
binary those nodes consume.

**The single design priority is reliability.** This device is a network-critical
service — if it hangs, every client on the LAN loses DNS. Favor fewer moving
parts, static allocation, and fail-safe behavior over features, cleverness, or
performance. When in doubt, choose the more boring and more robust option.

## Firmware roles

This project has **two distinct roles**, with different constraints. Don't
apply one role's rules to the other's code.

- **DNS-sinkhole** (`main/`) — the redundant, LAN-facing nodes that actually
  answer queries. This is the reliability-critical hot path. Everything in
  "Hard constraints" below applies here, unchanged.
- **Generator** (`generator-node/`) — builds `blocklist.bin`/`manifest.json`
  from public blocklists (fetch → parse → merge/dedupe → hash → sort →
  self-test). Not a query-serving hot path, so it's allowed to parse
  untrusted text, allocate dynamically, and make outbound HTTPS calls — none
  of that is permitted in the sinkhole role. Its one non-negotiable rule,
  carried over from the sinkhole's own philosophy: never let a bad or partial
  generation corrupt or overwrite what it's currently publishing (self-test
  before publish, atomic slot swap). Its own ESP-IDF project — own partition
  table, own Kconfig; not built alongside `main/`. (An earlier Go
  implementation of this same role, meant to run off-device on a
  server/Pi/NAS/CI, has been removed in favor of `generator-node/` running
  the whole fleet on dedicated hardware with no laptop/server dependency.)

## Hard constraints — do not violate

These apply to the **DNS-sinkhole firmware** (`main/`). The generator role's
own rules are covered above and don't inherit these (e.g. it *is* allowed to
parse and allocate dynamically).

- **Ethernet only, no WiFi.** Single supported board: the ESP32-P4-Function-EV-Board,
  RMII to its onboard IP101 PHY (`idf.py set-target esp32p4`). PHY driver and
  EMAC pin defaults live in `main/idf_component.yml`, `main/Kconfig.projbuild`,
  and `main/dns_sinkhole.c`'s `eth_start()`. (`generator-node/` is a separate
  ESP-IDF project — its own role, above — but the same P4-only hardware
  assumption applies there too.) Do not add WiFi code paths, and do not
  reintroduce a second MCU/PHY target without discussing it first.
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
        ▼   [generator role — generator-node/, its own ESP32-P4 firmware]
   fetch → parse hosts/domain/ABP format → merge → dedupe → FNV-1a-64 hash → sort ascending → self-test
        │
        ├─► blocklist.bin      (sorted array of little-endian uint64 hashes, format 2)
        └─► manifest.json       {format, version, size, sha256, count, url}
        │
        ▼   [served directly by the generator's HTTP server]
   DNS-sinkhole nodes (main/) poll manifest on a timer → if version changed:
        verify format matches → download blob → inactive data slot →
        verify sha256 + size + MIN count
        → pass: record active slot in NVS, load into new PSRAM buffer,
                atomic pointer swap, free old buffer
        → fail: discard, keep serving previous list, retry next cycle
```

Key invariants:
- The **FNV-1a hash function must be byte-identical** between the sinkhole
  firmware (`domain_hash` in `dns_sinkhole.c`, 64-bit) and the generator
  (`domain_hash` in `generator-node/components/blocklist_pipeline/hash.c`). If
  you change one, change both, bump the manifest `format` field (currently 2)
  so a firmware/generator mismatch is refused rather than silently corrupting
  lookups, and update the pinned parity vectors in
  `generator-node/components/blocklist_pipeline/test/host_main.c`.
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

- `make build flash monitor` (see `Makefile`) — `sdkconfig.local`, if present,
  is a gitignored extra defaults layer for machine-specific overrides (e.g.
  `CONFIG_SINKHOLE_MANIFEST_URL` pointed at your LAN IP) merged in on top of
  `sdkconfig.defaults`; it survives `fullclean`/`set-target` regenerating
  `sdkconfig`.
- menuconfig must have: SPIRAM enabled; IP101 PHY and RMII pin assignment
  matching the board; a custom partition table with dual data partitions for
  the blocklist (+ dual OTA partitions if firmware OTA is added).
- Network access is available in this container for `idf.py`/component-manager
  fetches, but assume the human builds/flashes onto real hardware.

## What NOT to do

- Do not add query logging, DoH/DoT, per-client rules, or caching unless
  explicitly asked. The owner chose reliability over features. (The one
  sanctioned exception: the best-effort UDP stats reporting in `main/stats.c`
  + the generator's in-RAM `/stats` UI, added at the owner's request. It must
  stay fire-and-forget — never let it grow into something the serve path
  depends on.)
- Do not parse public blocklists in the DNS-sinkhole firmware (`main/`).
  That's the generator role's job (`generator-node/`) — see "Firmware roles"
  above.
- Do not introduce dynamic allocation into the sinkhole's query path.
- Do not add WiFi.
- Do not use full-firmware OTA to deliver list updates.

## Style

- C for firmware — both the DNS-sinkhole (`main/`) and the generator-node
  (`generator-node/`).
- Keep functions small and readable; comment the *why*, especially around
  reliability trade-offs and the buffer/lifetime rules.
- Match the existing style in `dns_sinkhole.c` (static buffers, explicit sizes,
  clear separation between parse / lookup / respond / forward) for sinkhole
  code. The generator role is not held to the sinkhole's no-dynamic-allocation
  rule — see "Firmware roles" above.
