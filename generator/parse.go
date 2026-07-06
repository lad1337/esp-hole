package main

// Blocklist line parsing: hosts format, plain-domain lists, and simple
// AdBlock "||domain^" rules. Rules whose semantics a hash lookup cannot
// honor (modifiers, paths, wildcards inside the domain, exceptions) are
// skipped, never approximated.

import (
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// Hostnames that appear in hosts files but must never be blocked.
var ignoredHosts = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

var (
	ipv4Re = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	// Permissive but safe: labels of letters/digits/hyphen/underscore with at
	// least one dot. Underscores occur in real tracker domains.
	domainRe = regexp.MustCompile(
		`^[a-z0-9_]([a-z0-9_-]{0,62})?(\.[a-z0-9_]([a-z0-9_-]{0,62})?)+$`)
)

// normalizeDomain lowercases, strips a "*." wildcard prefix and trailing dot,
// and punycode-encodes non-ASCII names. Returns "" for anything that is not
// a blockable domain.
func normalizeDomain(token string) string {
	d := strings.ToLower(strings.TrimSpace(token))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" || len(d) > 253 || ignoredHosts[d] || ipv4Re.MatchString(d) {
		return ""
	}
	if !isASCII(d) {
		enc, err := idna.Lookup.ToASCII(d)
		if err != nil {
			return ""
		}
		d = enc
	}
	if !domainRe.MatchString(d) {
		return ""
	}
	return d
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// parseLine appends the domains found on one blocklist line to out and
// returns it.
func parseLine(line string, out []string) []string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return out
	}
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "@@") ||
		strings.HasPrefix(line, "[") {
		return out // ABP comment / exception / header — never block from these
	}
	if strings.HasPrefix(line, "||") {
		// Accept only exact "||domain^".
		if !strings.HasSuffix(line, "^") {
			return out
		}
		body := line[2 : len(line)-1]
		if strings.ContainsAny(body, "/^*$|") {
			return out
		}
		if d := normalizeDomain(body); d != "" {
			out = append(out, d)
		}
		return out
	}
	tokens := strings.Fields(line)
	if len(tokens) > 0 &&
		(ipv4Re.MatchString(tokens[0]) || strings.Contains(tokens[0], ":")) {
		tokens = tokens[1:] // hosts format: IP followed by one or more names
	}
	for _, t := range tokens {
		if d := normalizeDomain(t); d != "" {
			out = append(out, d)
		}
	}
	return out
}
