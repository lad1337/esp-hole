/* sha256_psa.h — device-only SHA-256 (see sha256_psa.c). Not part of the
 * portable core; not linked into the host test harness (test/sha256_host.c
 * is used there instead). Matches blocklist_sha256_fn's signature so it can
 * be plugged directly into a blocklist_platform_t on-device.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

void blocklist_sha256_psa(const uint8_t *data, size_t len, uint8_t out[32]);
