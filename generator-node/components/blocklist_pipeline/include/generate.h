/* generate.h — dedupe + sort + serialize + self-test. Port of the relevant
 * parts of generator/gen.go's generate()/selfTest() (gen.go:70-200).
 *
 * Key deviation from Go, confirmed in the generator-node plan: Go dedupes
 * twice (domain strings, then hashes) and keeps every domain string in
 * memory at once. This keeps only 64-bit hashes — no domain string is ever
 * retained past the moment it's hashed, which is what makes the working set
 * fit comfortably in PSRAM at real-world scale. See blocklist_builder_finish()
 * for how the self-test is adapted for a hash-only pipeline.
 *
 * Zero ESP-IDF headers (like parse.c/normalize.c/hash.c) except for the
 * platform seam below: allocation and SHA-256 are injected as function
 * pointers so this compiles and runs identically under plain host cc (see
 * test/) and the ESP-IDF/RISC-V build (see sha256_psa.c, and the
 * PSRAM-backed realloc wired up in main/ at milestone M3).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Single-function allocator (Lua-style): realloc(NULL, n) allocates,
 * realloc(p, 0) frees (returns NULL), realloc(p, n) resizes. On-device this
 * wraps heap_caps_realloc(..., MALLOC_CAP_SPIRAM); the host test harness
 * uses plain realloc(). */
typedef void *(*blocklist_realloc_fn)(void *ptr, size_t new_size);

/* One-shot SHA-256 over a complete buffer. On-device this wraps PSA Crypto
 * (sha256_psa.c); the host test harness links a throwaway reference
 * implementation (test/sha256_host.c) — never shipped. */
typedef void (*blocklist_sha256_fn)(const uint8_t *data, size_t len, uint8_t out[32]);

typedef struct {
    blocklist_realloc_fn realloc;
    blocklist_sha256_fn sha256;
} blocklist_platform_t;

/* Incremental builder: append domain hashes as they're discovered (e.g. from
 * parse_line()'s sink callback while streaming a source), then finish() to
 * dedupe+sort+serialize+self-test. Returns NULL on allocation failure.
 *
 * min_domains is the refuse-to-publish floor (checked in finish(), below),
 * runtime-configurable rather than hardcoded to BLOCKLIST_MIN_DOMAINS so
 * tests can use small values — production callers should pass
 * BLOCKLIST_MIN_DOMAINS (or the Kconfig-configured value, once milestone M7
 * adds one) explicitly. */
typedef struct blocklist_builder blocklist_builder_t;

blocklist_builder_t *blocklist_builder_create(const blocklist_platform_t *platform,
                                              size_t min_domains);

/* Hashes domain (len bytes) and appends it. Returns false if the append
 * failed (allocation failure growing the backing array) — the caller
 * decides whether/how to surface that (this component has no logging of its
 * own); the domain is simply not counted. */
bool blocklist_builder_add(blocklist_builder_t *b, const char *domain, size_t len);

void blocklist_builder_destroy(blocklist_builder_t *b);

typedef enum {
    BLOCKLIST_GENERATE_OK = 0,
    BLOCKLIST_GENERATE_ERR_ALLOC,
    BLOCKLIST_GENERATE_ERR_BELOW_MIN_DOMAINS,
    BLOCKLIST_GENERATE_ERR_SELFTEST, /* internal inconsistency — should never happen */
} blocklist_generate_status_t;

typedef struct {
    uint8_t *blob;   /* owned by the caller on success; free via platform->realloc(blob, 0) */
    size_t blob_len; /* == count * 8 */
    size_t count;
    uint8_t sha256[32];
} blocklist_artifact_t;

/* Dedupes (on hash, sort-then-unique), refuses if the resulting count is
 * below the builder's min_domains, serializes to a little-endian uint64_t[]
 * blob, computes its SHA-256, and self-tests: strict-ascending order, every
 * added hash round-trips via binary search against the final blob (not the
 * in-memory array — this also exercises serialization, the same as the
 * lookup path the firmware actually uses), and 3 fixed negative canaries
 * (mirroring generator/gen.go:187-191) are confirmed absent. On any failure
 * *out is left zeroed and the builder retains ownership of its own memory
 * (destroy it as normal); on success the builder no longer owns *out->blob.
 */
blocklist_generate_status_t blocklist_builder_finish(blocklist_builder_t *b,
                                                      blocklist_artifact_t *out);

/* Re-validates a blob against an expected SHA-256 and strict-ascending
 * order (size/count consistency, hash, sortedness — NOT the round-trip/
 * canary checks, which need the pre-dedupe hash list that isn't available
 * once persisted). Reusable both right after generation and when
 * re-validating a persisted blob loaded from flash (milestone M5) — mirrors
 * main/blocklist.c's load_slot() re-validation. */
bool blocklist_verify_blob(const uint8_t *blob, size_t blob_len, size_t count,
                           const uint8_t want_sha256[32], blocklist_sha256_fn sha256);
