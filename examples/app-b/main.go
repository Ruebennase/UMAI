package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/umai-protocol/umai/internal/demoapp"
)

func main() {
	cfg := demoapp.DefaultConfig("app-b")

	flag.StringVar(&cfg.ListenAddr, "addr", cfg.ListenAddr, "HTTP listen address")
	flag.StringVar(&cfg.PeerOrigin, "peer", cfg.PeerOrigin, "Allowed peer origin (App A)")
	flag.StringVar(&cfg.PeerEmbedURL, "embed-url", cfg.PeerEmbedURL, "URL of App A to embed in iframe")
	flag.StringVar(&cfg.DataDir, "data", cfg.DataDir, "Directory for local data storage")
	flag.StringVar(&cfg.AuthUsername, "user", cfg.AuthUsername, "Demo authentication username")
	flag.StringVar(&cfg.AuthPassword, "pass", cfg.AuthPassword, "Demo authentication password")
	flag.Int64Var(&cfg.MaxUploadSize, "max-upload", cfg.MaxUploadSize, "Max upload size in bytes")
	flag.BoolVar(&cfg.AllowDemoDefaults, "demo", cfg.AllowDemoDefaults, "Allow demo keys and default password on non-loopback addresses")
	staticDirFlag := flag.String("static", "", "Path to static directory (defaults to ./static next to binary/source)")

	flag.Parse()

	// Locate static files (never fall back to "." to prevent exposing DataDir or source tree)
	staticDir := *staticDirFlag
	if staticDir == "" {
		if info, err := os.Stat("static"); err == nil && info.IsDir() {
			staticDir = "static"
		} else if info, err := os.Stat("examples/app-b/static"); err == nil && info.IsDir() {
			staticDir = "examples/app-b/static"
		} else {
			log.Fatalf("Static assets directory not found (checked ./static and ./examples/app-b/static); specify -static <dir>")
		}
	}
	absStatic, _ := filepath.Abs(staticDir)

	server, err := demoapp.NewServer(cfg, absStatic)
	if err != nil {
		log.Fatalf("Failed to initialize Application B: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server B error: %v", err)
	}
}
