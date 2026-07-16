/* platform.h — the device-side blocklist_platform_t: PSRAM-backed allocator
 * (matches main/blocklist.c's heap_caps_malloc(..., MALLOC_CAP_SPIRAM)
 * pattern) + PSA SHA-256 (sha256_psa.c).
 */
#pragma once

#include "generate.h"

extern const blocklist_platform_t GENERATOR_PLATFORM;
