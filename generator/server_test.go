package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerEndToEnd(t *testing.T) {
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
	s := newServer(cfg)

	// Before any generation, every route must fail closed rather than serve
	// an empty/garbage list.
	ts := httptest.NewServer(s.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("manifest.json before generation: status %d, want 503", resp.StatusCode)
	}

	s.refresh()

	resp, err = http.Get(ts.URL + "/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest.json after refresh: status %d, want 200", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.Count != 20 {
		t.Errorf("manifest count = %d, want 20", m.Count)
	}
	if m.Format != Format {
		t.Errorf("manifest format = %d, want %d", m.Format, Format)
	}

	blobResp, err := http.Get(ts.URL + "/blocklist.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer blobResp.Body.Close()
	if blobResp.StatusCode != http.StatusOK {
		t.Fatalf("blocklist.bin: status %d, want 200", blobResp.StatusCode)
	}

	healthResp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: status %d, want 200", healthResp.StatusCode)
	}
}

func TestServerRefreshKeepsCurrentOnFailure(t *testing.T) {
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
	s := newServer(cfg)
	s.refresh()
	first := s.current.Load()
	if first == nil {
		t.Fatal("expected a published artifact after first refresh")
	}

	// Now point at a source that will fail the min-domains floor; refresh
	// must keep serving the previously published artifact.
	if err := os.WriteFile(src, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.refresh()
	second := s.current.Load()
	if second.art.Manifest.SHA256 != first.art.Manifest.SHA256 {
		t.Fatal("a failed refresh must not replace the currently published artifact")
	}
}

func TestServerRefreshUnchangedKeepsVersion(t *testing.T) {
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
	s := newServer(cfg)
	s.refresh()
	first := s.current.Load()

	s.refresh() // same source content, different version timestamp internally
	second := s.current.Load()
	if second.art.Manifest.Version != first.art.Manifest.Version {
		t.Errorf("unchanged sources should keep the previous version, got %s vs %s",
			second.art.Manifest.Version, first.art.Manifest.Version)
	}
}
