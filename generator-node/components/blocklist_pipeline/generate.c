/* generate.c — see generate.h. Port of generator/gen.go's generate()/
 * selfTest() (gen.go:70-200), adapted for hash-only dedupe.
 */
#include "generate.h"

#include <stdlib.h>
#include <string.h>

#include "hash.h"

struct blocklist_builder {
    const blocklist_platform_t *platform;
    uint64_t *hashes;
    size_t count;
    size_t capacity;
    size_t min_domains;
};

#define BUILDER_INITIAL_CAPACITY 4096

blocklist_builder_t *blocklist_builder_create(const blocklist_platform_t *platform,
                                              size_t min_domains)
{
    blocklist_builder_t *b = platform->realloc(NULL, sizeof(*b));
    if (!b) {
        return NULL;
    }
    b->platform = platform;
    b->hashes = NULL;
    b->count = 0;
    b->capacity = 0;
    b->min_domains = min_domains;
    return b;
}

static bool builder_reserve(blocklist_builder_t *b, size_t min_capacity)
{
    if (b->capacity >= min_capacity) {
        return true;
    }
    size_t new_cap = b->capacity ? b->capacity * 2 : BUILDER_INITIAL_CAPACITY;
    while (new_cap < min_capacity) {
        new_cap *= 2;
    }
    uint64_t *grown = b->platform->realloc(b->hashes, new_cap * sizeof(uint64_t));
    if (!grown) {
        return false;
    }
    b->hashes = grown;
    b->capacity = new_cap;
    return true;
}

bool blocklist_builder_add(blocklist_builder_t *b, const char *domain, size_t len)
{
    if (!builder_reserve(b, b->count + 1)) {
        return false;
    }
    b->hashes[b->count++] = domain_hash(domain, len);
    return true;
}

void blocklist_builder_destroy(blocklist_builder_t *b)
{
    if (!b) {
        return;
    }
    b->platform->realloc(b->hashes, 0);
    b->platform->realloc(b, 0);
}

static int cmp_u64(const void *a, const void *b)
{
    const uint64_t va = *(const uint64_t *)a;
    const uint64_t vb = *(const uint64_t *)b;
    if (va < vb) {
        return -1;
    }
    if (va > vb) {
        return 1;
    }
    return 0;
}

static uint64_t decode_le_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void encode_le_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

/* Binary search for target in a blob of count little-endian uint64_t
 * entries — the exact algorithm the firmware's blocklist_contains() uses
 * (see main/blocklist.c), so this also validates that a lookup against the
 * final serialized bytes works, not just against the in-memory array. */
static bool blob_contains(const uint8_t *blob, size_t count, uint64_t target)
{
    size_t lo = 0, hi = count;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const uint64_t v = decode_le_u64(blob + mid * 8);
        if (v < target) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo < count && decode_le_u64(blob + lo * 8) == target;
}

bool blocklist_verify_blob(const uint8_t *blob, size_t blob_len, size_t count,
                           const uint8_t want_sha256[32], blocklist_sha256_fn sha256)
{
    if (blob_len != count * 8) {
        return false;
    }
    uint8_t got_sha256[32];
    sha256(blob, blob_len, got_sha256);
    if (memcmp(got_sha256, want_sha256, sizeof(got_sha256)) != 0) {
        return false;
    }
    uint64_t prev = 0;
    for (size_t i = 0; i < count; i++) {
        const uint64_t h = decode_le_u64(blob + i * 8);
        if (i > 0 && h <= prev) {
            return false; /* not strictly ascending — binary search would break */
        }
        prev = h;
    }
    return true;
}

/* Fixed negative canaries: confirm at least one truly-unlisted name misses,
 * guarding against a degenerate lookup that always returns "found". Mirrors
 * generator/gen.go:187-191 exactly. */
static const char *const NEGATIVE_CANARIES[] = {
    "esp-hole-selftest-canary.example",
    "definitely-not-blocked.invalid",
    "self-test.test",
};
#define NEGATIVE_CANARY_COUNT (sizeof(NEGATIVE_CANARIES) / sizeof(NEGATIVE_CANARIES[0]))

blocklist_generate_status_t blocklist_builder_finish(blocklist_builder_t *b,
                                                      blocklist_artifact_t *out)
{
    memset(out, 0, sizeof(*out));

    /* Cheap short-circuit: dedup only ever removes entries, so if even the
     * raw (pre-dedupe) count is below the floor, the final count will be
     * too. Also sidesteps realloc(NULL, 0)'s implementation-defined result
     * when b->count is exactly 0. */
    if (b->count < b->min_domains) {
        return BLOCKLIST_GENERATE_ERR_BELOW_MIN_DOMAINS;
    }

    qsort(b->hashes, b->count, sizeof(uint64_t), cmp_u64);

    /* Upper-bound allocation (b->count entries); shrink after we know the
     * real (deduped) count. Serialize directly into the blob during the
     * dedup scan — one pass, no separate deduped-hashes buffer. */
    uint8_t *blob = b->platform->realloc(NULL, b->count * 8);
    if (!blob) {
        return BLOCKLIST_GENERATE_ERR_ALLOC;
    }

    size_t count = 0;
    for (size_t i = 0; i < b->count; i++) {
        if (i == 0 || b->hashes[i] != b->hashes[i - 1]) {
            encode_le_u64(blob + count * 8, b->hashes[i]);
            count++;
        }
    }

    if (count < b->min_domains) {
        b->platform->realloc(blob, 0);
        return BLOCKLIST_GENERATE_ERR_BELOW_MIN_DOMAINS;
    }

    const size_t blob_len = count * 8;
    uint8_t *shrunk = b->platform->realloc(blob, blob_len);
    if (shrunk) { /* shrink is best-effort; a failed shrink keeps the larger buffer */
        blob = shrunk;
    }

    uint8_t sha256[32];
    b->platform->sha256(blob, blob_len, sha256);

    if (!blocklist_verify_blob(blob, blob_len, count, sha256, b->platform->sha256)) {
        b->platform->realloc(blob, 0);
        return BLOCKLIST_GENERATE_ERR_SELFTEST;
    }
    for (size_t i = 0; i < b->count; i++) {
        if (!blob_contains(blob, count, b->hashes[i])) {
            b->platform->realloc(blob, 0);
            return BLOCKLIST_GENERATE_ERR_SELFTEST;
        }
    }
    for (size_t i = 0; i < NEGATIVE_CANARY_COUNT; i++) {
        const size_t len = strlen(NEGATIVE_CANARIES[i]);
        const uint64_t h = domain_hash(NEGATIVE_CANARIES[i], len);
        if (blob_contains(blob, count, h)) {
            b->platform->realloc(blob, 0);
            return BLOCKLIST_GENERATE_ERR_SELFTEST;
        }
    }

    out->blob = blob;
    out->blob_len = blob_len;
    out->count = count;
    memcpy(out->sha256, sha256, sizeof(sha256));
    return BLOCKLIST_GENERATE_OK;
}
