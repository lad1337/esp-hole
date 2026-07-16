/* sha256_psa.c — see sha256_psa.h. One-shot PSA Crypto call, the same API
 * main/blocklist.c:96-98 already uses to verify a loaded slot. ESP-IDF
 * only — excluded from the host test harness build.
 *
 * No error propagation (matches generator/gen.go's crypto/sha256.Sum256,
 * which also can't fail for valid input) — psa_hash_compute realistically
 * only fails on a crypto-subsystem fault, which isn't recoverable here
 * anyway.
 */
#include "sha256_psa.h"

#include "psa/crypto.h"

void blocklist_sha256_psa(const uint8_t *data, size_t len, uint8_t out[32])
{
    size_t out_len = 0;
    psa_hash_compute(PSA_ALG_SHA_256, data, len, out, 32, &out_len);
}
