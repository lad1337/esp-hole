/* hash.c — see hash.h. Literal copy of domain_hash()'s body from
 * main/dns_sinkhole.c:65-73 — deliberately not shared via a common source
 * file (this is a separate ESP-IDF project), so any future edit to one must
 * be manually mirrored to the other. Pinned parity vectors live in
 * test/host_main.c and generator/hash_test.go.
 */
#include "hash.h"

uint64_t domain_hash(const char *s, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}
