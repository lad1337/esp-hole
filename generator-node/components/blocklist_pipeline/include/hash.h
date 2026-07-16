/* hash.h — 64-bit FNV-1a. Must stay byte-identical to domain_hash() in
 * main/dns_sinkhole.c and fnv1a64() in generator/hash.go — see
 * blocklist_format.h.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

uint64_t domain_hash(const char *s, size_t len);
