package main

// The /stats web UI. All assets are embedded — the Docker image is built
// FROM scratch, so nothing can be read from disk at runtime.

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"time"
)

//go:embed webui
var webuiFS embed.FS

// statsRoutes registers the UI and its JSON API. When stats collection is
// disabled (s.stats == nil) the routes stay registered and answer 503, so a
// misconfigured bookmark gets a clear message instead of a 404.
func (s *server) statsRoutes(mux *http.ServeMux) {
	sub, err := fs.Sub(webuiFS, "webui")
	if err != nil {
		panic(err) // embed layout is fixed at compile time
	}

	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		page, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "missing embedded UI", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.Handle("GET /stats/ui/", http.StripPrefix("/stats/ui/",
		http.FileServerFS(sub)))

	mux.HandleFunc("GET /stats/api", func(w http.ResponseWriter, r *http.Request) {
		if s.stats == nil {
			http.Error(w, "stats disabled", http.StatusServiceUnavailable)
			return
		}
		rng := 24 * time.Hour
		if q := r.URL.Query().Get("range"); q != "" {
			if v, err := time.ParseDuration(q); err == nil {
				rng = v
			}
		}
		if rng < 10*time.Minute {
			rng = 10 * time.Minute
		}
		if max := time.Duration(s.cfg.StatsRetention); rng > max {
			rng = max
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(s.stats.snapshot(rng)); err != nil {
			log.Printf("WARNING: encoding stats response: %v", err)
		}
	})
}
