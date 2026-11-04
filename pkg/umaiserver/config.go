package umaiserver

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
)

// Config holds configuration parameters for a UMAI application server.
type Config struct {
	AppName         string // e.g. "Application A" or "Application B"
	Role            string // "app-a" or "app-b"
	ListenAddr      string // e.g. "127.0.0.1:8081"
	DataDir         string // Root directory for local storage
	PeerOrigin      string // Expected origin of the remote application (e.g. "http://127.0.0.1:8082")
	PeerEmbedURL    string // URL used by App B to embed App A (e.g. "http://127.0.0.1:8081?embedded=true")
	AuthUsername    string // Demo username
	AuthPassword    string // Demo password
	CookieName      string // Scoped cookie name to prevent collisions across ports on 127.0.0.1
	MaxUploadSize   int64  // Maximum upload size in bytes (e.g. 100MB)
	SessionSecret   string // Secret for signing/validating sessions
	AllowEmbedding  bool   // Whether CSP should allow embedding by PeerOrigin
}

// DefaultConfig returns a configuration populated with sensible defaults.
func DefaultConfig(role string) Config {
	if role == "app-b" {
		return Config{
			AppName:        "Application B",
			Role:           "app-b",
			ListenAddr:     getEnv("UMAI_LISTEN_ADDR", "127.0.0.1:8082"),
			DataDir:        getEnv("UMAI_DATA_DIR", "./data"),
			PeerOrigin:     getEnv("UMAI_PEER_ORIGIN", "http://127.0.0.1:8081"),
			PeerEmbedURL:   getEnv("UMAI_PEER_EMBED_URL", "http://127.0.0.1:8081?embedded=true"),
			AuthUsername:   getEnv("UMAI_AUTH_USER", "admin"),
			AuthPassword:   getEnv("UMAI_AUTH_PASS", "umai123"),
			CookieName:     getEnv("UMAI_COOKIE_NAME", "umai_session_b"),
			MaxUploadSize:  getEnvInt64("UMAI_MAX_UPLOAD_SIZE", 100*1024*1024), // 100 MB default
			SessionSecret:  randomHex(16),
			AllowEmbedding: false,
		}
	}

	// Default to app-a
	return Config{
		AppName:        "Application A",
		Role:           "app-a",
		ListenAddr:     getEnv("UMAI_LISTEN_ADDR", "127.0.0.1:8081"),
		DataDir:        getEnv("UMAI_DATA_DIR", "./data"),
		PeerOrigin:     getEnv("UMAI_PEER_ORIGIN", "http://127.0.0.1:8082"),
		PeerEmbedURL:   "",
		AuthUsername:   getEnv("UMAI_AUTH_USER", "admin"),
		AuthPassword:   getEnv("UMAI_AUTH_PASS", "umai123"),
		CookieName:     getEnv("UMAI_COOKIE_NAME", "umai_session_a"),
		MaxUploadSize:  getEnvInt64("UMAI_MAX_UPLOAD_SIZE", 100*1024*1024), // 100 MB default
		SessionSecret:  randomHex(16),
		AllowEmbedding: true,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return fallback
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "umai-session-secret-default"
	}
	return hex.EncodeToString(b)
}
