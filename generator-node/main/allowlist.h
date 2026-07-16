/* allowlist.h — manual "never block" list, filtered out of every generated
 * blob before publish (e.g. a false positive on one of the public sources).
 * Kconfig-only (rebuild to change), same convention as the source URLs —
 * see Kconfig.projbuild.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Parses CONFIG_GENERATOR_ALLOWLIST once. Call at boot, before the first
 * fetch cycle. */
void allowlist_init(void);

/* True if hash (from domain_hash() on an already-normalized domain) matches
 * an allowlisted entry. */
bool allowlist_contains(uint64_t hash);
