package main

import "testing"

// Vectors computed from a host-compiled mirror of domain_hash() in
// main/dns_sinkhole.c (offset 0xcbf29ce484222325, prime 0x100000001b3,
// 64-bit FNV-1a over raw bytes, no terminator). If these ever diverge from
// the firmware's output for the same inputs, blocklist lookups silently
// break — see the Format bump rule in gen.go.
func TestFNV1a64Vectors(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"", 0xcbf29ce484222325},
		{"a", 0xaf63dc4c8601ec8c},
		{"example.com", 0x576846634e2714c6},
		{"ads.example.com", 0xc0933158979aa55e},
		{"www.google.com", 0x654eb11a58fb5dfa},
		{"doubleclick.net", 0xdc8c04cd127775cd},
	}
	for _, c := range cases {
		if got := fnv1a64([]byte(c.in)); got != c.want {
			t.Errorf("fnv1a64(%q) = 0x%016x, want 0x%016x", c.in, got, c.want)
		}
	}
}
