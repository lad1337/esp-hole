package main

import (
	"reflect"
	"testing"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string
	}{
		{"empty", "", nil},
		{"comment", "# just a comment", nil},
		{"hosts ipv4", "0.0.0.0 ads.example.com", []string{"ads.example.com"}},
		{"hosts ipv4 multi", "0.0.0.0 ads.example.com tracker.example.com", []string{"ads.example.com", "tracker.example.com"}},
		{"hosts loopback ignored", "127.0.0.1 localhost", nil},
		{"plain domain", "ads.example.com", []string{"ads.example.com"}},
		{"plain with trailing comment", "ads.example.com # tracker", []string{"ads.example.com"}},
		{"wildcard prefix", "*.ads.example.com", []string{"ads.example.com"}},
		{"trailing dot", "ads.example.com.", []string{"ads.example.com"}},
		{"uppercase", "ADS.EXAMPLE.COM", []string{"ads.example.com"}},
		{"abp exact", "||ads.example.com^", []string{"ads.example.com"}},
		{"abp missing caret", "||ads.example.com", nil},
		{"abp with path modifier", "||ads.example.com^$third-party", nil},
		{"abp exception", "@@||ads.example.com^", nil},
		{"abp comment", "! this is a comment", nil},
		{"abp header bracket", "[Adblock Plus 2.0]", nil},
		{"bare ip", "203.0.113.5", nil},
		{"ipv6 hosts line", "::1 localhost", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseLine(c.line, nil)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseLine(%q) = %#v, want %#v", c.line, got, c.want)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"*.example.com", "example.com"},
		{"localhost", ""},
		{"broadcasthost", ""},
		{"0.0.0.0", ""},
		{"203.0.113.5", ""},
		{"not_a_domain", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeDomain(c.in); got != c.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseLineReusesScratch(t *testing.T) {
	// gen.go reuses the same backing slice across lines via out[:0]; make
	// sure appending on a reused slice doesn't leak stale entries.
	scratch := make([]string, 0, 8)
	scratch = parseLine("0.0.0.0 a.example.com b.example.com", scratch[:0])
	if len(scratch) != 2 {
		t.Fatalf("first call: got %v", scratch)
	}
	scratch = parseLine("0.0.0.0 c.example.com", scratch[:0])
	if !reflect.DeepEqual(scratch, []string{"c.example.com"}) {
		t.Fatalf("second call: got %v, want only c.example.com", scratch)
	}
}
