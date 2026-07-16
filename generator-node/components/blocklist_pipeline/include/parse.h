/* parse.h — port of parseLine() from generator/parse.go:65-102.
 *
 * One generic line classifier handles all 3 source shapes (hosts-file,
 * bare-domain-per-line, and a narrow "||domain^"-only AdGuard/ABP subset) —
 * there's no per-source dispatch on the Go side either, see parse.go's own
 * top-of-file comment.
 */
#pragma once

#include <stddef.h>

/* Called once per domain found on a line, already normalized (lowercase,
 * validated, NUL-terminated). ctx is opaque, passed through from parse_line's
 * caller — e.g. M3's fetch loop will pass a sink that hashes and appends
 * without ever retaining the string. */
typedef void (*domain_sink_fn)(const char *domain, size_t len, void *ctx);

/* Parses one blocklist line (no trailing newline expected, but harmless if
 * present — it's whitespace-trimmed like everything else) and calls sink()
 * for each domain found. Lines longer than the internal bound are dropped
 * silently (mirrors generator/gen.go's bufio.Scanner ErrTooLong-skip
 * behavior) — real blocklist lines are always far shorter than this. */
void parse_line(const char *line, size_t line_len, domain_sink_fn sink, void *ctx);
