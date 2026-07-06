package main

// fnv1a64 is 64-bit FNV-1a. It must stay byte-identical to domain_hash() in
// main/dns_sinkhole.c — if you change one, change both and bump Format.
// hash_test.go pins vectors cross-checked against the compiled C code.
func fnv1a64(data []byte) uint64 {
	h := uint64(0xcbf29ce484222325)
	for _, b := range data {
		h ^= uint64(b)
		h *= 0x100000001b3
	}
	return h
}
