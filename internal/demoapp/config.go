// Package demoapp provides the sample Application A and Application B web servers,
// demo authentication, and local document management layered on top of pkg/umaispool.
package demoapp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/umai-protocol/umai/pkg/umaispool"
)

// Config holds configuration parameters for a demo UMAI application server.
type Config struct {
	AppName           string // e.g. "Application A" or "Application B"
	Role              string // Local logical identity, e.g. "app-a" or "app-b"
	PeerRole          string // Peer logical identity (defaults to opposite demo role when empty)
	ListenAddr        string // e.g. "127.0.0.1:8081"
	DataDir           string // Root directory for local storage
	PeerOrigin        string // Expected origin of the remote application (e.g. "http://127.0.0.1:8082")
	PeerEmbedURL      string // URL used by App B to embed App A (e.g. "http://127.0.0.1:8081?embedded=true")
	AuthUsername      string // Demo username
	AuthPassword      string // Demo password
	CookieName        string // Scoped cookie name to prevent collisions across ports on 127.0.0.1
	MaxUploadSize     int64  // Maximum upload size in bytes (e.g. 100 MiB)
	SessionSecret     string // Secret for signing/validating sessions
	AllowEmbedding    bool   // Whether CSP should allow embedding by PeerOrigin
	SigningPrivateKey string // Hex-encoded Ed25519 private key or seed (auto-derived per role on loopback/demo if empty)
	PeerPublicKey     string // Hex-encoded Ed25519 public key of peer (auto-derived per role on loopback/demo if empty)
	AllowDemoDefaults bool   // Allow deterministic demo keys and default password on loopback (-demo)
}

// DefaultConfig returns a configuration populated with sensible defaults for the demo applications.
func DefaultConfig(role string) Config {
	if role == "app-b" {
		return Config{
			AppName:           "Application B",
			Role:              "app-b",
			PeerRole:          getEnv("UMAI_PEER_ROLE", "app-a"),
			ListenAddr:        getEnv("UMAI_LISTEN_ADDR", "127.0.0.1:8082"),
			DataDir:           getEnv("UMAI_DATA_DIR", "./data-b"),
			PeerOrigin:        getEnv("UMAI_PEER_ORIGIN", "http://127.0.0.1:8081"),
			PeerEmbedURL:      getEnv("UMAI_PEER_EMBED_URL", "http://127.0.0.1:8081?embedded=true"),
			AuthUsername:      getEnv("UMAI_AUTH_USER", "admin"),
			AuthPassword:      getEnv("UMAI_AUTH_PASS", "umai123"),
			CookieName:        getEnv("UMAI_COOKIE_NAME", "umai_session_b"),
			MaxUploadSize:     getEnvInt64("UMAI_MAX_UPLOAD_SIZE", umaispool.DefaultMaxUploadSize),
			SessionSecret:     randomHex(16),
			AllowEmbedding:    false,
			SigningPrivateKey: getEnv("UMAI_SIGNING_PRIVATE_KEY", ""),
			PeerPublicKey:     getEnv("UMAI_PEER_PUBLIC_KEY", ""),
			AllowDemoDefaults: getEnv("UMAI_DEMO", "") == "1" || getEnv("UMAI_DEMO", "") == "true",
		}
	}

	return Config{
		AppName:           "Application A",
		Role:              "app-a",
		PeerRole:          getEnv("UMAI_PEER_ROLE", "app-b"),
		ListenAddr:        getEnv("UMAI_LISTEN_ADDR", "127.0.0.1:8081"),
		DataDir:           getEnv("UMAI_DATA_DIR", "./data-a"),
		PeerOrigin:        getEnv("UMAI_PEER_ORIGIN", "http://127.0.0.1:8082"),
		PeerEmbedURL:      "",
		AuthUsername:      getEnv("UMAI_AUTH_USER", "admin"),
		AuthPassword:      getEnv("UMAI_AUTH_PASS", "umai123"),
		CookieName:        getEnv("UMAI_COOKIE_NAME", "umai_session_a"),
		MaxUploadSize:     getEnvInt64("UMAI_MAX_UPLOAD_SIZE", umaispool.DefaultMaxUploadSize),
		SessionSecret:     randomHex(16),
		AllowEmbedding:    true,
		SigningPrivateKey: getEnv("UMAI_SIGNING_PRIVATE_KEY", ""),
		PeerPublicKey:     getEnv("UMAI_PEER_PUBLIC_KEY", ""),
		AllowDemoDefaults: getEnv("UMAI_DEMO", "") == "1" || getEnv("UMAI_DEMO", "") == "true",
	}
}

// DeriveDemoKeyPair deterministically derives an Ed25519 key pair for a demo role ("app-a" or "app-b")
// strictly for local demo evaluation (-demo on loopback) and automated test suites.
func DeriveDemoKeyPair(role string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("UMAI-0.1-DEMO-ED25519-SEED:" + role))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// ResolveDemoSigningConfig builds an explicit umaispool.SigningConfig, using explicit hex keys when provided
// or deterministic demo keys when permitted by the demo server configuration.
func ResolveDemoSigningConfig(role, peerRole, privHex, peerPubHex string) (umaispool.SigningConfig, error) {
	localID := strings.TrimSpace(role)
	if localID == "" {
		localID = "app-a"
	}
	peerID := strings.TrimSpace(peerRole)
	if peerID == "" {
		if localID == "app-b" {
			peerID = "app-a"
		} else {
			peerID = "app-b"
		}
	}

	if strings.TrimSpace(privHex) != "" && strings.TrimSpace(peerPubHex) != "" {
		_, ownPriv, peerPub, err := umaispool.ParseSigningKeys(privHex, peerPubHex)
		if err != nil {
			return umaispool.SigningConfig{}, err
		}
		return umaispool.SigningConfig{
			LocalIdentity: localID,
			PeerIdentity:  peerID,
			PrivateKey:    ownPriv,
			PeerPublicKey: peerPub,
		}, nil
	}

	_, ownPriv := DeriveDemoKeyPair(localID)
	if strings.TrimSpace(privHex) != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(privHex))
		if err != nil {
			return umaispool.SigningConfig{}, fmt.Errorf("decoding signing private key hex: %w", err)
		}
		switch len(raw) {
		case ed25519.SeedSize:
			ownPriv = ed25519.NewKeyFromSeed(raw)
		case ed25519.PrivateKeySize:
			ownPriv = ed25519.PrivateKey(raw)
		default:
			return umaispool.SigningConfig{}, fmt.Errorf("invalid Ed25519 private key length: %d", len(raw))
		}
	}

	peerPub, _ := DeriveDemoKeyPair(peerID)
	if strings.TrimSpace(peerPubHex) != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(peerPubHex))
		if err != nil {
			return umaispool.SigningConfig{}, fmt.Errorf("decoding peer public key hex: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return umaispool.SigningConfig{}, fmt.Errorf("invalid Ed25519 public key length: %d", len(raw))
		}
		peerPub = ed25519.PublicKey(raw)
	}

	return umaispool.SigningConfig{
		LocalIdentity: localID,
		PeerIdentity:  peerID,
		PrivateKey:    ownPriv,
		PeerPublicKey: peerPub,
	}, nil
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
