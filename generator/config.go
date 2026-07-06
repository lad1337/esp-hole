package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config drives both generation and serving. See config.example.json.
type Config struct {
	// Sources are blocklist URLs (http/https) or local file paths.
	Sources []string `json:"sources"`
	// MinDomains is the refuse-to-publish floor. Must match
	// BLOCKLIST_MIN_DOMAINS in main/blocklist.h (the on-device validator
	// enforces the same floor).
	MinDomains int `json:"min_domains"`
	// Refresh is how often to re-fetch the sources and regenerate, as a Go
	// duration string ("6h", "30m").
	Refresh jsonDuration `json:"refresh"`
	// Listen is the HTTP listen address (":8080").
	Listen string `json:"listen"`
	// PublicURLBase is how the ESP nodes reach this server; the manifest's
	// "url" field becomes PublicURLBase + "/blocklist.bin".
	PublicURLBase string `json:"public_url_base"`
	// DataDir, if set, persists the last good blob + manifest so a restart
	// serves the previous list before the first regeneration completes.
	DataDir string `json:"data_dir"`
}

type jsonDuration time.Duration

func (d *jsonDuration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = jsonDuration(v)
	return nil
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		MinDomains: 10000,
		Refresh:    jsonDuration(6 * time.Hour),
		Listen:     ":8080",
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Sources) == 0 {
		return nil, fmt.Errorf("%s: no sources configured", path)
	}
	if cfg.PublicURLBase == "" {
		return nil, fmt.Errorf("%s: public_url_base is required (the ESP nodes fetch the blob from there)", path)
	}
	if cfg.MinDomains < 1 {
		return nil, fmt.Errorf("%s: min_domains must be positive", path)
	}
	return cfg, nil
}
