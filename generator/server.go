package main

// HTTP server mirroring the firmware's update philosophy: the currently
// published artifact keeps serving until a fully validated replacement is
// atomically swapped in. A failed regeneration changes nothing.

import (
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type server struct {
	cfg *Config
	// current holds *published; nil-able via atomic.Pointer for lock-free
	// reads from handlers.
	current atomic.Pointer[published]
}

type published struct {
	art          *Artifact
	manifestJSON []byte
}

func newServer(cfg *Config) *server {
	return &server{cfg: cfg}
}

// publish swaps in a validated artifact and optionally persists it.
func (s *server) publish(art *Artifact) {
	manifestJSON, err := marshalManifest(art.Manifest)
	if err != nil {
		log.Printf("ERROR: marshal manifest: %v", err) // cannot happen in practice
		return
	}
	s.current.Store(&published{art: art, manifestJSON: manifestJSON})
	log.Printf("published version %s: %d domains, %d bytes",
		art.Manifest.Version, art.Manifest.Count, len(art.Blob))
	if s.cfg.DataDir != "" {
		if err := writeArtifact(art, s.cfg.DataDir); err != nil {
			log.Printf("WARNING: persisting to %s failed: %v", s.cfg.DataDir, err)
		}
	}
}

// refresh regenerates from the sources. On failure the current artifact
// keeps serving. If the content is unchanged (same sha256), the version is
// kept so nodes don't re-download an identical list.
func (s *server) refresh() {
	version := time.Now().UTC().Format("20060102T150405Z")
	art, err := generate(s.cfg, version)
	if err != nil {
		log.Printf("ERROR: regeneration failed, keeping current list: %v", err)
		return
	}
	if cur := s.current.Load(); cur != nil &&
		cur.art.Manifest.SHA256 == art.Manifest.SHA256 {
		log.Printf("sources unchanged (sha256 match); keeping version %s",
			cur.art.Manifest.Version)
		return
	}
	s.publish(art)
}

// handler builds the HTTP mux. Split out from run() so tests can exercise
// the routes directly via httptest without binding a real listener.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /manifest.json", func(w http.ResponseWriter, r *http.Request) {
		cur := s.current.Load()
		if cur == nil {
			http.Error(w, "no blocklist generated yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(cur.manifestJSON)
	})
	mux.HandleFunc("GET /blocklist.bin", func(w http.ResponseWriter, r *http.Request) {
		cur := s.current.Load()
		if cur == nil {
			http.Error(w, "no blocklist generated yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(cur.art.Blob)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.current.Load() == nil {
			http.Error(w, "no artifact", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	return mux
}

func (s *server) run() error {
	// Restore the last good artifact first so a restart serves immediately,
	// even if the sources are down.
	if s.cfg.DataDir != "" {
		if art, err := loadArtifact(s.cfg.DataDir); err == nil {
			s.publish(art)
			log.Printf("restored persisted version %s", art.Manifest.Version)
		}
	}
	s.refresh()

	go func() {
		ticker := time.NewTicker(time.Duration(s.cfg.Refresh))
		for range ticker.C {
			s.refresh()
		}
	}()

	log.Printf("serving on %s (manifest url: %s/manifest.json)",
		s.cfg.Listen, s.cfg.PublicURLBase)
	return http.ListenAndServe(s.cfg.Listen, s.handler())
}
