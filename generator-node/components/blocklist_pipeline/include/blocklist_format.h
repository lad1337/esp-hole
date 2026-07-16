/* blocklist_format.h — constants that MUST stay in lockstep across three
 * independent implementations of the blocklist format:
 *
 *   - the Go generator:        generator/gen.go, generator/hash.go
 *   - the DNS-sinkhole firmware: main/dns_sinkhole.c, main/updater.c,
 *                                 main/blocklist.h
 *   - this generator-node firmware: this file, hash.c, generate.c (M2)
 *
 * If you change the hash algorithm or the manifest/blob layout, change it
 * everywhere above, bump BLOCKLIST_MANIFEST_FORMAT so a mismatch is refused
 * rather than silently corrupting lookups, and update the pinned parity
 * vectors in generator/hash_test.go and this component's test/host_main.c.
 */
#pragma once

/* Manifest "format" field. Must match MANIFEST_FORMAT in main/updater.c and
 * Format in generator/gen.go. */
#define BLOCKLIST_MANIFEST_FORMAT 2

/* Refuse-to-publish floor. Must match BLOCKLIST_MIN_DOMAINS in
 * main/blocklist.h and MinDomains's default in generator/config.go. This is
 * the guard against a successful-but-empty/truncated download from a broken
 * upstream — see CLAUDE.md's "Reliability guards that must exist". */
#define BLOCKLIST_MIN_DOMAINS 10000
