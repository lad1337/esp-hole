/* normalize.c — see normalize.h. Ported from generator/parse.go:16-61. */
#include "normalize.h"

#include <ctype.h>
#include <string.h>

/* Hostnames that appear in hosts files but must never be blocked — mirrors
 * generator/parse.go:16-21. */
static const char *const IGNORED_HOSTS[] = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
};
#define IGNORED_HOSTS_COUNT (sizeof(IGNORED_HOSTS) / sizeof(IGNORED_HOSTS[0]))

static int is_ignored_host(const char *s, size_t len)
{
    for (size_t i = 0; i < IGNORED_HOSTS_COUNT; i++) {
        if (strlen(IGNORED_HOSTS[i]) == len &&
            memcmp(IGNORED_HOSTS[i], s, len) == 0) {
            return 1;
        }
    }
    return 0;
}

int domain_is_ipv4_shape(const char *s, size_t len)
{
    size_t i = 0;
    for (int group = 0; group < 4; group++) {
        if (group > 0) {
            if (i >= len || s[i] != '.') {
                return 0;
            }
            i++;
        }
        const size_t start = i;
        while (i < len && s[i] >= '0' && s[i] <= '9') {
            i++;
        }
        const size_t glen = i - start;
        if (glen < 1 || glen > 3) {
            return 0;
        }
    }
    return i == len;
}

/* Manual scanner for generator/parse.go's domainRe:
 *   ^[a-z0-9_]([a-z0-9_-]{0,62})?(\.[a-z0-9_]([a-z0-9_-]{0,62})?)+$
 * i.e. 2+ dot-separated labels, each 1-63 chars, first char alnum/underscore,
 * remaining chars alnum/underscore/hyphen. Not worth a regex engine
 * dependency for one check. */
static int is_valid_domain_shape(const char *s, size_t len)
{
    size_t i = 0;
    int label_count = 0;
    while (i < len) {
        const size_t label_start = i;
        const char c0 = s[i];
        if (!(isalnum((unsigned char)c0) || c0 == '_')) {
            return 0;
        }
        i++;
        while (i < len && s[i] != '.') {
            const char c = s[i];
            if (!(isalnum((unsigned char)c) || c == '_' || c == '-')) {
                return 0;
            }
            i++;
        }
        if (i - label_start > 63) {
            return 0;
        }
        label_count++;
        if (i < len) {
            i++; /* skip the '.' */
            if (i >= len) {
                return 0; /* trailing dot with nothing after */
            }
        }
    }
    return label_count >= 2;
}

size_t normalize_domain(const char *token, size_t token_len, char *out, size_t out_sz)
{
    size_t start = 0, end = token_len;
    while (start < end && isspace((unsigned char)token[start])) {
        start++;
    }
    while (end > start && isspace((unsigned char)token[end - 1])) {
        end--;
    }
    size_t len = end - start;
    const char *s = token + start;

    if (len > 0 && s[len - 1] == '.') { /* at most one trailing dot */
        len--;
    }
    if (len >= 2 && s[0] == '*' && s[1] == '.') { /* at most one "*." prefix */
        s += 2;
        len -= 2;
    }

    if (len == 0 || len > 253 || len >= out_sz) {
        return 0;
    }

    char lower[256]; /* len <= 253 here, always fits */
    for (size_t i = 0; i < len; i++) {
        const char c = s[i];
        lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }

    if (is_ignored_host(lower, len) || domain_is_ipv4_shape(lower, len)) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)lower[i] >= 0x80) {
            return 0; /* deviation from Go: reject non-ASCII, no punycode */
        }
    }
    if (!is_valid_domain_shape(lower, len)) {
        return 0;
    }

    memcpy(out, lower, len);
    out[len] = '\0';
    return len;
}
