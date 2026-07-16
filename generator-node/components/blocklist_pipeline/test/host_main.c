/* host_main.c — plain-cc host test harness for the portable blocklist
 * pipeline core. No ESP-IDF, no hardware. Transcribes the same cases as
 * generator/parse_test.go and generator/hash_test.go so both
 * implementations are checked against the same expectations.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "normalize.h"
#include "hash.h"
#include "generate.h"

void blocklist_sha256_host(const uint8_t *data, size_t len, uint8_t out[32]);

static int g_failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        printf("FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        g_failures++; \
    } \
} while (0)

/* ---- parse_line ------------------------------------------------------- */

#define MAX_COLLECT 16
typedef struct {
    char items[MAX_COLLECT][256];
    int count;
} collector_t;

static void collect_sink(const char *domain, size_t len, void *ctx)
{
    collector_t *c = (collector_t *)ctx;
    if (c->count < MAX_COLLECT) {
        memcpy(c->items[c->count], domain, len);
        c->items[c->count][len] = '\0';
        c->count++;
    }
}

static int collector_equals(const collector_t *c, const char *const *want, int want_count)
{
    if (c->count != want_count) {
        return 0;
    }
    for (int i = 0; i < want_count; i++) {
        if (strcmp(c->items[i], want[i]) != 0) {
            return 0;
        }
    }
    return 1;
}

typedef struct {
    const char *name;
    const char *line;
    const char *const *want;
    int want_count;
} parse_case_t;

static void test_parse_line(void)
{
    static const char *const w_ads[] = {"ads.example.com"};
    static const char *const w_ads_tracker[] = {"ads.example.com", "tracker.example.com"};

    const parse_case_t cases[] = {
        {"empty", "", NULL, 0},
        {"comment", "# just a comment", NULL, 0},
        {"hosts ipv4", "0.0.0.0 ads.example.com", w_ads, 1},
        {"hosts ipv4 multi", "0.0.0.0 ads.example.com tracker.example.com", w_ads_tracker, 2},
        {"hosts loopback ignored", "127.0.0.1 localhost", NULL, 0},
        {"plain domain", "ads.example.com", w_ads, 1},
        {"plain with trailing comment", "ads.example.com # tracker", w_ads, 1},
        {"wildcard prefix", "*.ads.example.com", w_ads, 1},
        {"trailing dot", "ads.example.com.", w_ads, 1},
        {"uppercase", "ADS.EXAMPLE.COM", w_ads, 1},
        {"abp exact", "||ads.example.com^", w_ads, 1},
        {"abp missing caret", "||ads.example.com", NULL, 0},
        {"abp with path modifier", "||ads.example.com^$third-party", NULL, 0},
        {"abp exception", "@@||ads.example.com^", NULL, 0},
        {"abp comment", "! this is a comment", NULL, 0},
        {"abp header bracket", "[Adblock Plus 2.0]", NULL, 0},
        {"bare ip", "203.0.113.5", NULL, 0},
        {"ipv6 hosts line", "::1 localhost", NULL, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        collector_t got;
        memset(&got, 0, sizeof(got));
        parse_line(cases[i].line, strlen(cases[i].line), collect_sink, &got);
        CHECK(collector_equals(&got, cases[i].want, cases[i].want_count),
              "parse_line(%s) [%s]: got %d domains, want %d",
              cases[i].line, cases[i].name, got.count, cases[i].want_count);
    }
}

/* ---- normalize_domain --------------------------------------------------- */

static void test_normalize_domain(void)
{
    const struct { const char *in; const char *want; } cases[] = {
        {"Example.COM", "example.com"},
        {"example.com.", "example.com"},
        {"*.example.com", "example.com"},
        {"localhost", ""},
        {"broadcasthost", ""},
        {"0.0.0.0", ""},
        {"203.0.113.5", ""},
        {"not_a_domain", ""},
        {"", ""},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char out[256];
        const size_t n = normalize_domain(cases[i].in, strlen(cases[i].in), out, sizeof(out));
        const char *got = (n > 0) ? out : "";
        CHECK(strcmp(got, cases[i].want) == 0,
              "normalize_domain(%s) = %s, want %s", cases[i].in, got, cases[i].want);
    }

    /* Deliberate deviation from the Go version (confirmed decision, see
     * blocklist-pipeline plan): non-ASCII is rejected, not punycode-encoded. */
    const char non_ascii[] = "m\xc3\xbcller.example.com"; /* "müller.example.com" (UTF-8) */
    char out[256];
    const size_t n = normalize_domain(non_ascii, strlen(non_ascii), out, sizeof(out));
    CHECK(n == 0, "normalize_domain(non-ASCII) should reject, got n=%zu", n);
}

/* ---- domain_hash (FNV-1a 64) --------------------------------------------- */

static void test_fnv_vectors(void)
{
    const struct { const char *in; uint64_t want; } cases[] = {
        {"", 0xcbf29ce484222325ULL},
        {"a", 0xaf63dc4c8601ec8cULL},
        {"example.com", 0x576846634e2714c6ULL},
        {"ads.example.com", 0xc0933158979aa55eULL},
        {"www.google.com", 0x654eb11a58fb5dfaULL},
        {"doubleclick.net", 0xdc8c04cd127775cdULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const uint64_t got = domain_hash(cases[i].in, strlen(cases[i].in));
        CHECK(got == cases[i].want, "domain_hash(%s) = 0x%016llx, want 0x%016llx",
              cases[i].in, (unsigned long long)got, (unsigned long long)cases[i].want);
    }
}

/* Known-answer vectors for sha256_host.c itself — without this, every other
 * test only proves the reference implementation is internally consistent
 * (compute == compare), not that it computes *correct* SHA-256. */
static void test_sha256_host_vectors(void)
{
    const struct { const char *in; const char *want_hex; } cases[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t got[32];
        blocklist_sha256_host((const uint8_t *)cases[i].in, strlen(cases[i].in), got);
        char got_hex[65];
        for (int k = 0; k < 32; k++) {
            snprintf(got_hex + k * 2, 3, "%02x", got[k]);
        }
        CHECK(strcmp(got_hex, cases[i].want_hex) == 0,
              "sha256_host(%s) = %s, want %s", cases[i].in, got_hex, cases[i].want_hex);
    }
}

/* ---- generate.c: blocklist_builder / blocklist_verify_blob --------------- */

static void *host_realloc(void *ptr, size_t new_size)
{
    /* generate.h documents realloc(p, 0) as "frees p, returns NULL" — plain
     * libc realloc's behavior at size 0 is implementation-defined, so pin it
     * down explicitly rather than relying on the host libc's choice. */
    if (new_size == 0) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, new_size);
}

static const blocklist_platform_t HOST_PLATFORM = {
    .realloc = host_realloc,
    .sha256 = blocklist_sha256_host,
};

static bool blob_has_hash(const uint8_t *blob, size_t count, uint64_t target)
{
    for (size_t i = 0; i < count; i++) {
        uint64_t v = 0;
        for (int k = 7; k >= 0; k--) {
            v = (v << 8) | blob[i * 8 + k];
        }
        if (v == target) {
            return true;
        }
    }
    return false;
}

/* Mirrors generator/gen_test.go's TestGenerateSuccessAndRoundTrip. */
static void test_generate_success_and_roundtrip(void)
{
    blocklist_builder_t *b = blocklist_builder_create(&HOST_PLATFORM, 10);
    CHECK(b != NULL, "builder_create failed");
    if (!b) {
        return;
    }

    char buf[64];
    for (int i = 0; i < 20; i++) {
        const int n = snprintf(buf, sizeof(buf), "d%d.example.com", i);
        CHECK(blocklist_builder_add(b, buf, (size_t)n), "add(%s) failed", buf);
    }

    blocklist_artifact_t art;
    const blocklist_generate_status_t status = blocklist_builder_finish(b, &art);
    CHECK(status == BLOCKLIST_GENERATE_OK, "finish() status = %d, want OK", status);
    if (status == BLOCKLIST_GENERATE_OK) {
        CHECK(art.count == 20, "count = %zu, want 20", art.count);
        CHECK(art.blob_len == 20 * 8, "blob_len = %zu, want 160", art.blob_len);
        for (int i = 0; i < 20; i++) {
            const int n = snprintf(buf, sizeof(buf), "d%d.example.com", i);
            const uint64_t h = domain_hash(buf, (size_t)n);
            CHECK(blob_has_hash(art.blob, art.count, h),
                  "domain %s missing from published blob", buf);
        }
        HOST_PLATFORM.realloc(art.blob, 0);
    }
    blocklist_builder_destroy(b);
}

/* Mirrors generator/gen_test.go's TestGenerateBelowFloorRefuses. */
static void test_generate_below_floor_refuses(void)
{
    blocklist_builder_t *b = blocklist_builder_create(&HOST_PLATFORM, 10000);
    CHECK(b != NULL, "builder_create failed");
    if (!b) {
        return;
    }
    blocklist_builder_add(b, "a.example.com", strlen("a.example.com"));
    blocklist_builder_add(b, "b.example.com", strlen("b.example.com"));

    blocklist_artifact_t art;
    const blocklist_generate_status_t status = blocklist_builder_finish(b, &art);
    CHECK(status == BLOCKLIST_GENERATE_ERR_BELOW_MIN_DOMAINS,
          "finish() status = %d, want ERR_BELOW_MIN_DOMAINS", status);
    blocklist_builder_destroy(b);
}

/* Mirrors generator/gen_test.go's TestSelfTestNegativeCheckFailure: a blob
 * built from exactly the negative-canary domains must fail self-test. */
static void test_generate_canary_triggers_selftest_failure(void)
{
    blocklist_builder_t *b = blocklist_builder_create(&HOST_PLATFORM, 1);
    CHECK(b != NULL, "builder_create failed");
    if (!b) {
        return;
    }
    static const char *const canaries[] = {
        "esp-hole-selftest-canary.example",
        "definitely-not-blocked.invalid",
        "self-test.test",
    };
    for (size_t i = 0; i < 3; i++) {
        blocklist_builder_add(b, canaries[i], strlen(canaries[i]));
    }

    blocklist_artifact_t art;
    const blocklist_generate_status_t status = blocklist_builder_finish(b, &art);
    CHECK(status == BLOCKLIST_GENERATE_ERR_SELFTEST,
          "finish() with only canary domains status = %d, want ERR_SELFTEST", status);
    blocklist_builder_destroy(b);
}

/* Mirrors generator/gen_test.go's TestSelfTestSizeMismatch/ShaMismatch/
 * NotSorted: exercise blocklist_verify_blob() directly against hand-crafted
 * (including deliberately corrupted) blobs. */
static void test_verify_blob(void)
{
    const uint64_t h1 = domain_hash("a.example.com", strlen("a.example.com"));
    const uint64_t h2 = domain_hash("b.example.com", strlen("b.example.com"));
    const uint64_t lo = h1 < h2 ? h1 : h2;
    const uint64_t hi = h1 < h2 ? h2 : h1;

    uint8_t blob[16];
    for (int k = 0; k < 8; k++) {
        blob[k] = (uint8_t)(lo >> (8 * k));
        blob[8 + k] = (uint8_t)(hi >> (8 * k));
    }
    uint8_t sha256[32];
    blocklist_sha256_host(blob, sizeof(blob), sha256);

    CHECK(blocklist_verify_blob(blob, sizeof(blob), 2, sha256, blocklist_sha256_host),
          "verify_blob: valid blob rejected");
    CHECK(!blocklist_verify_blob(blob, sizeof(blob), 3, sha256, blocklist_sha256_host),
          "verify_blob: size/count mismatch accepted");

    uint8_t wrong_sha256[32];
    memset(wrong_sha256, 0, sizeof(wrong_sha256));
    CHECK(!blocklist_verify_blob(blob, sizeof(blob), 2, wrong_sha256, blocklist_sha256_host),
          "verify_blob: sha256 mismatch accepted");

    uint8_t unsorted[16];
    memcpy(unsorted, blob + 8, 8);
    memcpy(unsorted + 8, blob, 8);
    uint8_t unsorted_sha256[32];
    blocklist_sha256_host(unsorted, sizeof(unsorted), unsorted_sha256);
    CHECK(!blocklist_verify_blob(unsorted, sizeof(unsorted), 2, unsorted_sha256, blocklist_sha256_host),
          "verify_blob: unsorted blob accepted");
}

int main(void)
{
    test_parse_line();
    test_normalize_domain();
    test_fnv_vectors();
    test_sha256_host_vectors();
    test_generate_success_and_roundtrip();
    test_generate_below_floor_refuses();
    test_generate_canary_triggers_selftest_failure();
    test_verify_blob();

    if (g_failures == 0) {
        printf("PASS: all host tests passed\n");
        return 0;
    }
    printf("FAIL: %d assertion(s) failed\n", g_failures);
    return 1;
}
