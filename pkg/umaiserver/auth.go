package umaiserver

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	SessionCookieName = "umai_session"
	SessionDuration   = 24 * time.Hour
)

// Session represents an active authenticated user session.
type Session struct {
	ID        string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// AuthManager manages server-side sessions.
type AuthManager struct {
	mu            sync.RWMutex
	sessions      map[string]*Session
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
		cookieName:    cookieName,
		validUsername: username,
		validPassword: password,
	}
}

// CookieName returns the configured cookie name.
func (am *AuthManager) CookieName() string {
	return am.cookieName
}

// Authenticate verifies credentials and returns a new session ID if valid.
func (am *AuthManager) Authenticate(username, password string) (string, bool) {
	if username != am.validUsername || password != am.validPassword {
		return "", false
	}

	sessionID := generateSessionID()
	sess := &Session{
		ID:        sessionID,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(SessionDuration),
	}

	am.mu.Lock()
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

// SetSessionCookie writes the session cookie onto the HTTP response.
func (am *AuthManager) SetSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	sameSite := http.SameSiteLaxMode
	if isSecure {
		sameSite = http.SameSiteNoneMode
	}

	cookie := &http.Cookie{
		Name:     am.cookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(SessionDuration),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: sameSite,
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie clears the session cookie.
func (am *AuthManager) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	cookie := &http.Cookie{
		Name:     am.cookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
	}
	http.SetCookie(w, cookie)
}

// GetSessionID extracts the session ID from cookie or Authorization header.
func (am *AuthManager) GetSessionID(r *http.Request) string {
	// First check explicit headers (takes precedence, preventing cross-port cookie collisions)
	if h := r.Header.Get("X-UMAI-Session"); h != "" {
		return h
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Fallback to scoped cookie
	if c, err := r.Cookie(am.cookieName); err == nil && c.Value != "" {
		return c.Value
	}

	// Legacy fallback to default cookie name
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
