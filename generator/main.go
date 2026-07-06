package main

// Entry point: either serve continuously (default) or run one generation and
// exit (-oneshot), for CI/manual runs and image builds that just want a
// blocklist.bin + manifest.json on disk.

import (
	"flag"
	"log"
	"os"
	"time"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config JSON")
	oneshot := flag.Bool("oneshot", false, "generate once, write to -data-dir (or config's data_dir), and exit")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if *oneshot {
		if cfg.DataDir == "" {
			log.Fatal("-oneshot requires data_dir set in the config")
		}
		version := time.Now().UTC().Format("20060102T150405Z")
		art, err := generate(cfg, version)
		if err != nil {
			log.Fatalf("generate: %v", err)
		}
		if err := writeArtifact(art, cfg.DataDir); err != nil {
			log.Fatalf("write %s: %v", cfg.DataDir, err)
		}
		log.Printf("wrote version %s: %d domains, %d bytes to %s",
			art.Manifest.Version, art.Manifest.Count, len(art.Blob), cfg.DataDir)
		os.Exit(0)
	}

	if err := newServer(cfg).run(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
