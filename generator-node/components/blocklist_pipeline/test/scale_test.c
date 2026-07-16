/* scale_test.c — not part of `make test`. Feeds the real, live-fetched
 * blocklist sources (see the `scale-data`/`scale-test` Makefile targets)
 * through the full parse -> builder -> finish() pipeline and reports real
 * counts, timings, and peak RSS — the numbers the generator-node plan's M2
 * milestone calls for before any of this touches hardware.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

#include "generate.h"
#include "parse.h"

void blocklist_sha256_host(const uint8_t *data, size_t len, uint8_t out[32]);

static void *host_realloc(void *ptr, size_t new_size)
{
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

typedef struct {
    blocklist_builder_t *builder;
    long lines;
    long added;
} feed_ctx_t;

static void feed_sink(const char *domain, size_t len, void *vctx)
{
    feed_ctx_t *ctx = (feed_ctx_t *)vctx;
    if (blocklist_builder_add(ctx->builder, domain, len)) {
        ctx->added++;
    }
}

static void process_file(const char *path, feed_ctx_t *ctx)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "WARNING: cannot open %s (non-fatal, matches the generator's "
                        "per-source fault tolerance)\n", path);
        return;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    long file_lines = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        size_t len = (size_t)n;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            len--;
        }
        parse_line(line, len, feed_sink, ctx);
        file_lines++;
    }
    free(line);
    fclose(f);
    printf("  %s: %ld lines\n", path, file_lines);
    ctx->lines += file_lines;
}

static double elapsed_s(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <source-file>...\n", argv[0]);
        return 2;
    }

    feed_ctx_t ctx = {0};
    ctx.builder = blocklist_builder_create(&HOST_PLATFORM, 10000);
    if (!ctx.builder) {
        fprintf(stderr, "builder_create failed\n");
        return 1;
    }

    printf("parsing %d source file(s):\n", argc - 1);
    struct timespec t_parse_start, t_parse_end;
    clock_gettime(CLOCK_MONOTONIC, &t_parse_start);
    for (int i = 1; i < argc; i++) {
        process_file(argv[i], &ctx);
    }
    clock_gettime(CLOCK_MONOTONIC, &t_parse_end);

    blocklist_artifact_t art;
    struct timespec t_finish_start, t_finish_end;
    clock_gettime(CLOCK_MONOTONIC, &t_finish_start);
    const blocklist_generate_status_t status = blocklist_builder_finish(ctx.builder, &art);
    clock_gettime(CLOCK_MONOTONIC, &t_finish_end);

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);

    printf("\n");
    printf("lines read:        %ld\n", ctx.lines);
    printf("domains hashed:    %ld (pre-dedupe, i.e. builder_add() calls)\n", ctx.added);
    printf("parse time:        %.2fs\n", elapsed_s(t_parse_start, t_parse_end));
    printf("finish() time:     %.2fs (sort + dedupe + serialize + self-test)\n",
           elapsed_s(t_finish_start, t_finish_end));
#ifdef __APPLE__
    printf("peak RSS:          %.1f MB\n", (double)ru.ru_maxrss / 1e6); /* macOS: bytes */
#else
    printf("peak RSS:          %.1f MB\n", (double)ru.ru_maxrss / 1e3); /* Linux: KB */
#endif

    if (status != BLOCKLIST_GENERATE_OK) {
        printf("\ngenerate FAILED: status=%d\n", status);
        blocklist_builder_destroy(ctx.builder);
        return 1;
    }

    printf("final count:       %zu domains\n", art.count);
    printf("blob size:         %zu bytes (%.2f MB)\n", art.blob_len, (double)art.blob_len / 1e6);
    printf("sha256:            ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", art.sha256[i]);
    }
    printf("\n");

    HOST_PLATFORM.realloc(art.blob, 0);
    blocklist_builder_destroy(ctx.builder);
    return 0;
}
