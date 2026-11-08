package umaiserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	SessionCookieName         = "umai_session"
	SessionDuration           = 24 * time.Hour
	MaxActiveSessions         = 10000
	BootstrapTransactionTTL   = 5 * time.Minute
	MaxBootstrapTransactions  = 1000
)

var (
	ErrBootstrapNotFound      = errors.New("bootstrap transaction not found or expired")
	ErrBootstrapPending       = errors.New("bootstrap transaction awaiting top-level authorization")
	ErrBootstrapInvalidKey    = errors.New("invalid P-256 public key for bootstrap transaction")
	ErrBootstrapInvalidProof  = errors.New("invalid proof-of-possession signature or opener nonce")
)

// BootstrapTransaction represents a short-lived, ephemeral-key-bound authentication handoff
// between a cross-origin embedded iframe and a top-level authentication window.
// AuthSecret is minted exclusively upon AuthorizeBootstrap and returned only to the authenticated
// top-level window (which passes it over window.opener.postMessage in browser memory), preventing
// remote session-fixation or phishing-link transaction takeover.
type BootstrapTransaction struct {
	TxID         string
	OpenerNonce  string
	Challenge    string
	AuthSecret   string
	PublicKey    *ecdsa.PublicKey
	Authorized   bool
	AuthorizedBy string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Session represents an active authenticated user session.
type Session struct {
	ID        string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthManager manages server-side sessions and iframe proof-of-possession bootstrap transactions.
type AuthManager struct {
	mu            sync.RWMutex
	sessions      map[string]*Session
	bootstraps    map[string]*BootstrapTransaction
	cookieName    string
	validUsername string
	validPassword string
}

// NewAuthManager initializes session management.
func NewAuthManager(cookieName, username, password string) *AuthManager {
	if cookieName == "" {
		cookieName = SessionCookieName
	}
	return &AuthManager{
		sessions:      make(map[string]*Session),
		bootstraps:    make(map[string]*BootstrapTransaction),
		cookieName:    cookieName,
		validUsername: username,
		validPassword: password,
	}
}

// CookieName returns the configured cookie name.
func (am *AuthManager) CookieName() string {
	return am.cookieName
}

// Authenticate verifies credentials in constant time and returns a new session ID if valid.
func (am *AuthManager) Authenticate(username, password string) (string, bool) {
	uHash := sha256.Sum256([]byte(username))
	expUHash := sha256.Sum256([]byte(am.validUsername))
	pHash := sha256.Sum256([]byte(password))
	expPHash := sha256.Sum256([]byte(am.validPassword))

	uMatch := subtle.ConstantTimeCompare(uHash[:], expUHash[:])
	pMatch := subtle.ConstantTimeCompare(pHash[:], expPHash[:])
	if (uMatch & pMatch) != 1 {
		return "", false
	}

	now := time.Now()
	sessionID := generateSessionID()
	sess := &Session{
		ID:        sessionID,
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(SessionDuration),
	}

	am.mu.Lock()
	for id, existing := range am.sessions {
		if now.After(existing.ExpiresAt) {
			delete(am.sessions, id)
		}
	}
	if len(am.sessions) >= MaxActiveSessions {
		// Evict oldest session if cap reached
		var oldestID string
		var oldestTime time.Time
		for id, existing := range am.sessions {
			if oldestID == "" || existing.CreatedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = existing.CreatedAt
			}
		}
		if oldestID != "" {
			delete(am.sessions, oldestID)
		}
	}
	am.sessions[sessionID] = sess
	am.mu.Unlock()

	return sessionID, true
}

// ValidateSession checks if a session ID is valid and not expired.
func (am *AuthManager) ValidateSession(sessionID string) (*Session, bool) {
	if sessionID == "" {
		return nil, false
	}

	am.mu.RLock()
	sess, exists := am.sessions[sessionID]
	am.mu.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(sess.ExpiresAt) {
		am.mu.Lock()
		delete(am.sessions, sessionID)
		am.mu.Unlock()
		return nil, false
	}

	return sess, true
}

// RevokeSession invalidates a session.
func (am *AuthManager) RevokeSession(sessionID string) {
	am.mu.Lock()
	delete(am.sessions, sessionID)
	am.mu.Unlock()
}

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Only trust X-Forwarded-Proto when request arrives from a local reverse proxy (loopback)
	if r.Header.Get("X-Forwarded-Proto") == "https" && isLoopbackHostPort(r.RemoteAddr) {
		return true
	}
	return false
}

func isLoopbackHostPort(addr string) bool {
	if addr == "" {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SetSessionCookie writes the session cookie onto the HTTP response.
func (am *AuthManager) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	isSecure := isHTTPSRequest(r)
	sameSite := http.SameSiteLaxMode
	if isSecure {
		sameSite = http.SameSiteNoneMode
	}

	cookie := &http.Cookie{
		Name:        am.cookieName,
		Value:       sessionID,
		Path:        "/",
		Expires:     time.Now().Add(SessionDuration),
		HttpOnly:    true,
		Secure:      isSecure,
		SameSite:    sameSite,
		Partitioned: isSecure,
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie clears the session cookie.
func (am *AuthManager) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	isSecure := isHTTPSRequest(r)
	sameSite := http.SameSiteLaxMode
	if isSecure {
		sameSite = http.SameSiteNoneMode
	}
	cookie := &http.Cookie{
		Name:        am.cookieName,
		Value:       "",
		Path:        "/",
		Expires:     time.Unix(0, 0),
		MaxAge:      -1,
		HttpOnly:    true,
		Secure:      isSecure,
		SameSite:    sameSite,
		Partitioned: isSecure,
	}
	http.SetCookie(w, cookie)
}

// GetSessionID extracts the session ID strictly from the HttpOnly session cookie.
func (am *AuthManager) GetSessionID(r *http.Request) string {
	// Scoped HttpOnly cookie (e.g. umai_session_a or umai_session_b)
	if c, err := r.Cookie(am.cookieName); err == nil && c.Value != "" {
		return c.Value
	}

	// Fallback to default cookie name
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}

	return ""
}

func generateSessionID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateRandomHex(numBytes int) string {
	b := make([]byte, numBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// parseP256UncompressedPublicKey parses a 65-byte uncompressed NIST P-256 point (0x04 || X || Y) encoded in hex.
func parseP256UncompressedPublicKey(pubHex string) (*ecdsa.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(raw) != 65 || raw[0] != 0x04 {
		return nil, ErrBootstrapInvalidKey
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	if !curve.IsOnCurve(x, y) {
		return nil, ErrBootstrapInvalidKey
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// InitBootstrap registers a pending authentication transaction bound to an ephemeral P-256 public key
// generated inside the embedded iframe.
func (am *AuthManager) InitBootstrap(pubKeyHex string) (*BootstrapTransaction, error) {
	pubKey, err := parseP256UncompressedPublicKey(pubKeyHex)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tx := &BootstrapTransaction{
		TxID:        generateRandomHex(16),
		OpenerNonce: generateRandomHex(16),
		Challenge:   generateRandomHex(32),
		PublicKey:   pubKey,
		CreatedAt:   now,
		ExpiresAt:   now.Add(BootstrapTransactionTTL),
	}

	am.mu.Lock()
	for id, existing := range am.bootstraps {
		if now.After(existing.ExpiresAt) {
			delete(am.bootstraps, id)
		}
	}
	if len(am.bootstraps) >= MaxBootstrapTransactions {
		var oldestID string
		var oldestTime time.Time
		for id, existing := range am.bootstraps {
			if oldestID == "" || existing.CreatedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = existing.CreatedAt
			}
		}
		if oldestID != "" {
			delete(am.bootstraps, oldestID)
		}
	}
	am.bootstraps[tx.TxID] = tx
	am.mu.Unlock()

	return tx, nil
}

// AuthorizeBootstrap is called by an authenticated top-level window to approve a pending iframe transaction.
// Mints and returns a single-use 256-bit AuthSecret exclusively to the authenticated top-level response so the
// popup can pass it directly to window.opener via same-origin postMessage (preventing remote URL phishing takeover).
func (am *AuthManager) AuthorizeBootstrap(txID, openerNonce, username string) (string, error) {
	if txID == "" || openerNonce == "" || username == "" {
		return "", ErrBootstrapInvalidProof
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	tx, exists := am.bootstraps[txID]
	if !exists || time.Now().After(tx.ExpiresAt) {
		delete(am.bootstraps, txID)
		return "", ErrBootstrapNotFound
	}

	nHash := sha256.Sum256([]byte(openerNonce))
	expHash := sha256.Sum256([]byte(tx.OpenerNonce))
	if subtle.ConstantTimeCompare(nHash[:], expHash[:]) != 1 {
		return "", ErrBootstrapInvalidProof
	}

	if tx.AuthSecret == "" {
		tx.AuthSecret = generateRandomHex(32)
	}
	tx.Authorized = true
	tx.AuthorizedBy = username
	return tx.AuthSecret, nil
}

// RedeemBootstrap verifies both the top-level AuthSecret (delivered in-browser via window.opener) and
// the embedded iframe's ECDSA P-256 signature (IEEE P1363 r||s format from WebCrypto) over
// "UMAI-BOOTSTRAP-V1:<txID>:<challenge>:<authSecret>". Once verified, the transaction is consumed
// (single-use) and a new authenticated session ID is minted for the iframe context.
func (am *AuthManager) RedeemBootstrap(txID, authSecret, sigHex string) (string, string, error) {
	if txID == "" {
		return "", "", ErrBootstrapNotFound
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	tx, exists := am.bootstraps[txID]
	if !exists || time.Now().After(tx.ExpiresAt) {
		delete(am.bootstraps, txID)
		return "", "", ErrBootstrapNotFound
	}

	if !tx.Authorized || tx.AuthorizedBy == "" || tx.AuthSecret == "" {
		return "", "", ErrBootstrapPending
	}

	if strings.TrimSpace(authSecret) == "" {
		delete(am.bootstraps, txID)
		return "", "", ErrBootstrapInvalidProof
	}
	sHash := sha256.Sum256([]byte(strings.TrimSpace(authSecret)))
	expSHash := sha256.Sum256([]byte(tx.AuthSecret))
	if subtle.ConstantTimeCompare(sHash[:], expSHash[:]) != 1 {
		delete(am.bootstraps, txID)
		return "", "", ErrBootstrapInvalidProof
	}

	rawSig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(rawSig) != 64 {
		delete(am.bootstraps, txID)
		return "", "", ErrBootstrapInvalidProof
	}

	rInt := new(big.Int).SetBytes(rawSig[:32])
	sInt := new(big.Int).SetBytes(rawSig[32:])

	msg := fmt.Sprintf("UMAI-BOOTSTRAP-V1:%s:%s:%s", tx.TxID, tx.Challenge, tx.AuthSecret)
	digest := sha256.Sum256([]byte(msg))

	if !ecdsa.Verify(tx.PublicKey, digest[:], rInt, sInt) {
		delete(am.bootstraps, txID)
		return "", "", ErrBootstrapInvalidProof
	}

	// Single-use: consume bootstrap transaction immediately
	username := tx.AuthorizedBy
	delete(am.bootstraps, txID)

	now := time.Now()
	for id, existing := range am.sessions {
		if now.After(existing.ExpiresAt) {
			delete(am.sessions, id)
		}
	}
	if len(am.sessions) >= MaxActiveSessions {
		var oldestID string
		var oldestTime time.Time
		for id, existing := range am.sessions {
			if oldestID == "" || existing.CreatedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = existing.CreatedAt
			}
		}
		if oldestID != "" {
			delete(am.sessions, oldestID)
		}
	}

	sessionID := generateSessionID()
	am.sessions[sessionID] = &Session{
		ID:        sessionID,
		Username:  username,
		CreatedAt: now,
		ExpiresAt: now.Add(SessionDuration),
	}

	return sessionID, username, nil
}
