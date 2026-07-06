package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// buildBlob is a test helper: sorted little-endian uint64 blob from domains.
func buildBlob(domains ...string) []byte {
	hashes := make([]uint64, len(domains))
	for i, d := range domains {
		hashes[i] = fnv1a64([]byte(d))
	}
	slices.Sort(hashes)
	blob := make([]byte, 8*len(hashes))
	for i, h := range hashes {
		binary.LittleEndian.PutUint64(blob[8*i:], h)
	}
	return blob
}

func validManifestFor(blob []byte) Manifest {
	sum := sha256.Sum256(blob)
	return Manifest{
		Format:  Format,
		Version: "test",
		Size:    len(blob),
		SHA256:  hex.EncodeToString(sum[:]),
		Count:   len(blob) / 8,
		URL:     "http://example.invalid/blocklist.bin",
	}
}

func manyTestDomains(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "d" + strings.Repeat("x", 1) + string(rune('a'+i%26)) + ".example.com" + string(rune('0'+i%10))
	}
	// Ensure uniqueness deterministically.
	seen := make(map[string]bool, n)
	for i, d := range out {
		for seen[d] {
			d += "x"
		}
		seen[d] = true
		out[i] = d
	}
	return out
}

func TestGenerateSuccessAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "list.txt")
	domains := manyTestDomains(20)
	if err := os.WriteFile(src, []byte(strings.Join(domains, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Sources:       []string{src},
		MinDomains:    10,
		PublicURLBase: "http://example.invalid",
	}
	art, err := generate(cfg, "v1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if art.Manifest.Count != 20 {
		t.Errorf("count = %d, want 20", art.Manifest.Count)
	}
	if art.Manifest.URL != "http://example.invalid/blocklist.bin" {
		t.Errorf("url = %q", art.Manifest.URL)
	}

	dataDir := filepath.Join(dir, "data")
	if err := writeArtifact(art, dataDir); err != nil {
		t.Fatalf("writeArtifact: %v", err)
	}
	loaded, err := loadArtifact(dataDir)
	if err != nil {
		t.Fatalf("loadArtifact: %v", err)
	}
	if loaded.Manifest.SHA256 != art.Manifest.SHA256 {
		t.Errorf("round-trip sha256 mismatch")
	}
}

func TestGenerateBelowFloorRefuses(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(src, []byte("a.example.com\nb.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Sources:       []string{src},
		MinDomains:    10000,
		PublicURLBase: "http://example.invalid",
	}
	if _, err := generate(cfg, "v1"); err == nil {
		t.Fatal("expected error for below-floor domain count, got nil")
	}
}

func TestGenerateDeadSourceIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	domains := manyTestDomains(15)
	if err := os.WriteFile(good, []byte(strings.Join(domains, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Sources:       []string{filepath.Join(dir, "missing.txt"), good},
		MinDomains:    10,
		PublicURLBase: "http://example.invalid",
	}
	art, err := generate(cfg, "v1")
	if err != nil {
		t.Fatalf("generate should tolerate one dead source: %v", err)
	}
	if art.Manifest.Count != 15 {
		t.Errorf("count = %d, want 15", art.Manifest.Count)
	}
}

func TestSelfTestSizeMismatch(t *testing.T) {
	blob := buildBlob("a.example.com", "b.example.com")
	m := validManifestFor(blob)
	m.Size = m.Size + 8 // lie about size
	art := &Artifact{Blob: blob, Manifest: m}
	errs := selfTest(art, nil)
	if len(errs) == 0 {
		t.Fatal("expected size mismatch error")
	}
}

func TestSelfTestShaMismatch(t *testing.T) {
	blob := buildBlob("a.example.com", "b.example.com")
	m := validManifestFor(blob)
	m.SHA256 = strings.Repeat("0", 64) // wrong on purpose
	art := &Artifact{Blob: blob, Manifest: m}
	errs := selfTest(art, nil)
	if !containsSubstr(errs, "sha256") {
		t.Fatalf("expected a sha256 error, got %v", errs)
	}
}

func TestSelfTestNotSorted(t *testing.T) {
	blob := buildBlob("a.example.com", "b.example.com", "c.example.com")
	// Swap the first two 8-byte entries to break ordering.
	tmp := make([]byte, 8)
	copy(tmp, blob[0:8])
	copy(blob[0:8], blob[8:16])
	copy(blob[8:16], tmp)
	m := validManifestFor(blob) // sha/size still match this (unsorted) blob
	art := &Artifact{Blob: blob, Manifest: m}
	errs := selfTest(art, nil)
	if !containsSubstr(errs, "ascending") {
		t.Fatalf("expected an ascending-order error, got %v", errs)
	}
}

func TestSelfTestMissingDomain(t *testing.T) {
	blob := buildBlob("a.example.com", "b.example.com")
	m := validManifestFor(blob)
	art := &Artifact{Blob: blob, Manifest: m}
	domains := map[string]bool{"a.example.com": true, "b.example.com": true, "c.example.com": true}
	errs := selfTest(art, domains)
	if !containsSubstr(errs, "not found in the blob") {
		t.Fatalf("expected a missing-domain error, got %v", errs)
	}
}

func TestSelfTestNegativeCheckFailure(t *testing.T) {
	// Build a blob that (implausibly) contains exactly the canary hashes, so
	// the negative-lookup check itself must fail.
	blob := buildBlob("esp-hole-selftest-canary.example", "definitely-not-blocked.invalid", "self-test.test")
	m := validManifestFor(blob)
	art := &Artifact{Blob: blob, Manifest: m}
	errs := selfTest(art, map[string]bool{})
	if !containsSubstr(errs, "negative lookup") {
		t.Fatalf("expected a negative-lookup error, got %v", errs)
	}
}

func containsSubstr(errs []string, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
