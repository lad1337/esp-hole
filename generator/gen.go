package main

// Generation pipeline: fetch sources → parse → hash (FNV-1a 64) → dedupe →
// sort → self-test. The output is only ever handed to the server / written
// to disk after the self-test passes ("refuse to publish", same spirit as
// the firmware's refuse-to-swap).

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

// Format identifies the blob layout + hash scheme. 2 = uint64 LE FNV-1a.
// The firmware refuses manifests with any other value (MANIFEST_FORMAT in
// main/updater.c) — bump both together with any hash change.
const Format = 2

type Manifest struct {
	Format  int    `json:"format"`
	Version string `json:"version"`
	Size    int    `json:"size"`
	SHA256  string `json:"sha256"`
	Count   int    `json:"count"`
	URL     string `json:"url"`
}

// Artifact is one validated, publishable generation result.
type Artifact struct {
	Blob     []byte
	Manifest Manifest
}

var httpClient = &http.Client{Timeout: 60 * time.Second}

func readSource(src string) (io.ReadCloser, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		req, err := http.NewRequest(http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "esp-hole-blocklist-gen/2")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
	return os.Open(src)
}

// generate builds a validated artifact from cfg's sources. A dead source is
// a warning, not fatal — the min-domains floor makes the final publish/refuse
// call so a broken upstream can never silently shrink the list.
func generate(cfg *Config, version string) (*Artifact, error) {
	domains := make(map[string]bool)
	scratch := make([]string, 0, 8)
	for _, src := range cfg.Sources {
		body, err := readSource(src)
		if err != nil {
			log.Printf("WARNING: failed to read %s: %v", src, err)
			continue
		}
		before := len(domains)
		scanner := bufio.NewScanner(body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			scratch = parseLine(scanner.Text(), scratch[:0])
			for _, d := range scratch {
				domains[d] = true
			}
		}
		body.Close()
		if err := scanner.Err(); err != nil {
			log.Printf("WARNING: error reading %s: %v", src, err)
			continue
		}
		log.Printf("%s: +%d new domains", src, len(domains)-before)
	}

	if len(domains) < cfg.MinDomains {
		return nil, fmt.Errorf(
			"only %d domains (< %d); refusing to publish — check the sources",
			len(domains), cfg.MinDomains)
	}

	hashSet := make(map[uint64]bool, len(domains))
	for d := range domains {
		hashSet[fnv1a64([]byte(d))] = true
	}
	hashes := make([]uint64, 0, len(hashSet))
	for h := range hashSet {
		hashes = append(hashes, h)
	}
	slices.Sort(hashes)

	blob := make([]byte, 8*len(hashes))
	for i, h := range hashes {
		binary.LittleEndian.PutUint64(blob[8*i:], h)
	}

	sum := sha256.Sum256(blob)
	art := &Artifact{
		Blob: blob,
		Manifest: Manifest{
			Format:  Format,
			Version: version,
			Size:    len(blob),
			SHA256:  hex.EncodeToString(sum[:]),
			Count:   len(hashes),
			URL:     strings.TrimSuffix(cfg.PublicURLBase, "/") + "/blocklist.bin",
		},
	}
	if errs := selfTest(art, domains); len(errs) > 0 {
		return nil, fmt.Errorf("self-test failed: %s", strings.Join(errs, "; "))
	}
	log.Printf("self-test OK: manifest consistent, blob sorted, %d domains round-trip, negative lookup misses",
		len(domains))
	return art, nil
}

// selfTest verifies the artifact is exactly what the ESP nodes expect:
// consistent with its manifest, strictly ascending (binary search depends on
// it), and a full round-trip — every input domain must be found by the same
// lookup the firmware performs.
func selfTest(art *Artifact, domains map[string]bool) []string {
	var errs []string
	m := art.Manifest

	if len(art.Blob) != m.Size || len(art.Blob) != m.Count*8 {
		errs = append(errs, fmt.Sprintf(
			"size mismatch: blob %d bytes, manifest size %d, count %d * 8",
			len(art.Blob), m.Size, m.Count))
		return errs // nothing below is meaningful with a bad size
	}
	sum := sha256.Sum256(art.Blob)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		errs = append(errs, "sha256 of blob does not match manifest")
	}

	hashes := make([]uint64, m.Count)
	for i := range hashes {
		hashes[i] = binary.LittleEndian.Uint64(art.Blob[8*i:])
	}
	for i := 1; i < len(hashes); i++ {
		if hashes[i-1] >= hashes[i] {
			errs = append(errs, "blob is not strictly ascending — binary search would break")
			return errs
		}
	}

	contains := func(name string) bool {
		h := fnv1a64([]byte(name))
		i := sort.Search(len(hashes), func(i int) bool { return hashes[i] >= h })
		return i < len(hashes) && hashes[i] == h
	}

	missing := 0
	for d := range domains {
		if !contains(d) {
			missing++
		}
	}
	if missing > 0 {
		errs = append(errs, fmt.Sprintf("%d input domains not found in the blob", missing))
	}

	// Negative check: a name that is not in the input set must miss (any of
	// these colliding with a real entry is astronomically unlikely; if all
	// of them "hit", the lookup itself is broken).
	canaryMissed := false
	for _, c := range []string{
		"esp-hole-selftest-canary.example",
		"definitely-not-blocked.invalid",
		"self-test.test",
	} {
		if !domains[c] && !contains(c) {
			canaryMissed = true
		}
	}
	if !canaryMissed {
		errs = append(errs, "negative lookup check failed: unlisted names all hit")
	}
	return errs
}

// marshalManifest renders the manifest as the JSON the ESP nodes parse.
func marshalManifest(m Manifest) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// writeArtifact persists blob + manifest atomically (tmp + rename, blob
// first) so a crash can never leave a half-written pair.
func writeArtifact(art *Artifact, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeAtomic(dir+"/blocklist.bin", art.Blob); err != nil {
		return err
	}
	manifestJSON, err := marshalManifest(art.Manifest)
	if err != nil {
		return err
	}
	return writeAtomic(dir+"/manifest.json", manifestJSON)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadArtifact reads a previously persisted blob + manifest pair and
// re-validates their consistency (not the domain round-trip — the domain set
// is gone — but size, sha and sortedness, same as the firmware does on boot).
func loadArtifact(dir string) (*Artifact, error) {
	manifestJSON, err := os.ReadFile(dir + "/manifest.json")
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(dir + "/blocklist.bin")
	if err != nil {
		return nil, err
	}
	art := &Artifact{Blob: blob, Manifest: m}
	if m.Format != Format {
		return nil, fmt.Errorf("persisted format %d != %d", m.Format, Format)
	}
	if errs := selfTest(art, nil); len(errs) > 0 {
		return nil, fmt.Errorf("persisted artifact invalid: %s", strings.Join(errs, "; "))
	}
	return art, nil
}
