/* parse.c — see parse.h. Ported from generator/parse.go:65-102. */
#include "parse.h"
#include "normalize.h"

#include <ctype.h>
#include <string.h>

#define PARSE_MAX_LINE   2048 /* generous for real blocklist lines; longer → drop */
#define PARSE_MAX_TOKENS 64   /* generous for hosts lines with many names */

static void emit_token(const char *tok, size_t tok_len, domain_sink_fn sink, void *ctx)
{
    char out[256];
    const size_t n = normalize_domain(tok, tok_len, out, sizeof(out));
    if (n > 0) {
        sink(out, n, ctx);
    }
}

void parse_line(const char *line_in, size_t line_len, domain_sink_fn sink, void *ctx)
{
    if (line_len > PARSE_MAX_LINE) {
        return; /* too long — drop, mirrors bufio.Scanner's ErrTooLong-skip */
    }
    char buf[PARSE_MAX_LINE];
    memcpy(buf, line_in, line_len);

    /* Comment stripping: everything from the first '#' onward. */
    const char *hash = memchr(buf, '#', line_len);
    size_t len = hash ? (size_t)(hash - buf) : line_len;

    /* Trim leading/trailing ASCII whitespace (also eats a trailing \r). */
    size_t start = 0;
    while (start < len && isspace((unsigned char)buf[start])) {
        start++;
    }
    size_t end = len;
    while (end > start && isspace((unsigned char)buf[end - 1])) {
        end--;
    }
    const char *line = buf + start;
    len = end - start;

    if (len == 0) {
        return;
    }
    if (line[0] == '!' || line[0] == '[' ||
        (len >= 2 && line[0] == '@' && line[1] == '@')) {
        return; /* ABP comment / exception / header — never block from these */
    }
    if (len >= 2 && line[0] == '|' && line[1] == '|') {
        /* Accept only exact "||domain^". */
        if (line[len - 1] != '^') {
            return;
        }
        const char *body = line + 2;
        const size_t body_len = len - 3;
        for (size_t i = 0; i < body_len; i++) {
            const char c = body[i];
            if (c == '/' || c == '^' || c == '*' || c == '$' || c == '|') {
                return;
            }
        }
        emit_token(body, body_len, sink, ctx);
        return;
    }

    /* Whitespace-tokenize (strings.Fields equivalent). */
    size_t tok_start[PARSE_MAX_TOKENS];
    size_t tok_len[PARSE_MAX_TOKENS];
    int ntok = 0;
    size_t i = 0;
    while (i < len && ntok < PARSE_MAX_TOKENS) {
        while (i < len && isspace((unsigned char)line[i])) {
            i++;
        }
        if (i >= len) {
            break;
        }
        const size_t tstart = i;
        while (i < len && !isspace((unsigned char)line[i])) {
            i++;
        }
        tok_start[ntok] = tstart;
        tok_len[ntok] = i - tstart;
        ntok++;
    }

    int first = 0;
    if (ntok > 0) {
        const char *t0 = line + tok_start[0];
        const size_t t0_len = tok_len[0];
        int has_colon = 0;
        for (size_t k = 0; k < t0_len; k++) {
            if (t0[k] == ':') {
                has_colon = 1;
                break;
            }
        }
        if (domain_is_ipv4_shape(t0, t0_len) || has_colon) {
            first = 1; /* hosts format: IP followed by one or more names */
        }
    }
    for (int k = first; k < ntok; k++) {
        emit_token(line + tok_start[k], tok_len[k], sink, ctx);
    }
}
