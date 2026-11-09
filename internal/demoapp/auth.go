package demoapp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	SessionCookieName = "umai_session"
	SessionDuration   = 24 * time.Hour
	MaxActiveSessions = 10000
)

// Session represents an active authenticated demo user session.
type Session struct {
	ID        string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthManager manages server-side demo sessions with scoped HttpOnly cookies.
type AuthManager struct {
	mu            sync.RWMutex
	sessions      map[string]*Session
	cookieName    string
	validUsername string
	validPassword string
}

// NewAuthManager initializes demo session management.
func NewAuthManager(cookieName, username, password string) *AuthManager {
	if cookieName == "" {
		cookieName = SessionCookieName
	}
	return &AuthManager{
		sessions:      make(map[string]*Session),
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

	now := time.Now().UTC()
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

	if time.Now().UTC().After(sess.ExpiresAt) {
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
	if strings.EqualFold(host, "localhost") {
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
		Expires:     time.Now().UTC().Add(SessionDuration),
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
		Expires:     time.Unix(0, 0).UTC(),
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
	if c, err := r.Cookie(am.cookieName); err == nil && c.Value != "" {
		return c.Value
	}
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
