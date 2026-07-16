/* platform.c — see platform.h. */
#include "platform.h"

#include <stdlib.h>

#include "esp_heap_caps.h"

#include "sha256_psa.h"

/* Lua-style realloc contract (see generate.h): NULL+n allocates, p+0 frees,
 * p+n resizes. heap_caps_malloc-allocated memory frees via plain free(), the
 * same pattern main/blocklist.c:83,123 already uses — not heap_caps_free(). */
static void *psram_realloc(void *ptr, size_t new_size)
{
    if (new_size == 0) {
        free(ptr);
        return NULL;
    }
    if (ptr == NULL) {
        return heap_caps_malloc(new_size, MALLOC_CAP_SPIRAM);
    }
    return heap_caps_realloc(ptr, new_size, MALLOC_CAP_SPIRAM);
}

const blocklist_platform_t GENERATOR_PLATFORM = {
    .realloc = psram_realloc,
    .sha256 = blocklist_sha256_psa,
};
