/* normalize.h — port of normalizeDomain() from generator/parse.go:34-52.
 *
 * Deviation from the Go version (a deliberate, confirmed decision — see the
 * generator-node plan): non-ASCII tokens are rejected outright rather than
 * punycode-encoded via golang.org/x/net/idna. This matches every other
 * malformed-input case — dropped, never approximated.
 */
#pragma once

#include <stddef.h>

/* Normalizes token (token_len bytes, not necessarily NUL-terminated) into a
 * lowercase, validated domain string written into out (capacity out_sz,
 * NUL-terminated on success). Returns the length written (excluding the
 * NUL), or 0 if the token is not a blockable domain — mirrors Go's
 * normalizeDomain() returning "".
 */
size_t normalize_domain(const char *token, size_t token_len, char *out, size_t out_sz);

/* Shared with parse.c: true if s (len bytes) matches ^\d{1,3}(\.\d{1,3}){3}$
 * (shape only, no range check — mirrors generator/parse.go's ipv4Re). */
int domain_is_ipv4_shape(const char *s, size_t len);
