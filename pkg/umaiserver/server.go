package umaiserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	_ = mime.AddExtensionType(".css", "text/css; charset=utf-8")
	_ = mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
	_ = mime.AddExtensionType(".html", "text/html; charset=utf-8")
	_ = mime.AddExtensionType(".json", "application/json; charset=utf-8")
}

// Server coordinates HTTP routes, static files, auth, and storage.
type Server struct {
	cfg     Config
	storage *Storage
	auth    *AuthManager
	mux     *http.ServeMux
	fs      http.Handler // static assets handler
}

// NewServer creates a new UMAI server.
func NewServer(cfg Config, staticDir string) (*Server, error) {
	if cfg.PeerOrigin != "" {
		u, err := url.Parse(cfg.PeerOrigin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid peer origin %q: must be an http:// or https:// origin", cfg.PeerOrigin)
		}
	}

	if !cfg.AllowDemoDefaults && !isLoopbackHostPort(cfg.ListenAddr) {
		if strings.TrimSpace(cfg.SigningPrivateKey) == "" || strings.TrimSpace(cfg.PeerPublicKey) == "" {
			return nil, fmt.Errorf("refusing to use deterministic demo Ed25519 keys on non-loopback address %q: set UMAI_SIGNING_PRIVATE_KEY and UMAI_PEER_PUBLIC_KEY (or pass -demo)", cfg.ListenAddr)
		}
		if cfg.AuthPassword == "" || cfg.AuthPassword == "umai123" {
			return nil, fmt.Errorf("refusing to use default demo password on non-loopback address %q: set -pass / UMAI_AUTH_PASS (or pass -demo)", cfg.ListenAddr)
		}
	}

	storage, err := NewStorage(cfg.DataDir, cfg.MaxUploadSize)
	if err != nil {
		return nil, fmt.Errorf("initializing storage: %w", err)
	}

	ownPub, ownPriv, peerPub, err := ParseKeyPair(cfg.Role, cfg.SigningPrivateKey, cfg.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("initializing signing keys: %w", err)
	}
	storage.SetKeys(cfg.Role, ownPub, ownPriv, peerPub)

	auth := NewAuthManager(cfg.CookieName, cfg.AuthUsername, cfg.AuthPassword)

	s := &Server{
		cfg:     cfg,
		storage: storage,
		auth:    auth,
		mux:     http.NewServeMux(),
		fs:      newStaticFileHandler(staticDir),
	}

	s.registerRoutes()
	return s, nil
}

func newStaticFileHandler(staticDir string) http.Handler {
	fileServer := http.FileServer(http.Dir(staticDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		ext := filepath.Ext(path)
		if ext == ".css" {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else if ext == ".js" {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fileServer.ServeHTTP(w, r)
	})
}

// Handler returns the HTTP handler with global middleware.
func (s *Server) Handler() http.Handler {
	return s.securityMiddleware(s.mux)
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	server := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}
	if s.cfg.SigningPrivateKey == "" || s.cfg.PeerPublicKey == "" {
		log.Printf("[%s] SECURITY NOTICE: Using deterministic role demo Ed25519 keys. Set UMAI_SIGNING_PRIVATE_KEY and UMAI_PEER_PUBLIC_KEY in production.", s.cfg.AppName)
	}
	if s.cfg.AuthPassword == "umai123" {
		log.Printf("[%s] SECURITY NOTICE: Using default demo credentials (%s / umai123). Override via -user/-pass or UMAI_AUTH_USER/UMAI_AUTH_PASS.", s.cfg.AppName, s.cfg.AuthUsername)
	}
	log.Printf("[%s] Starting on http://%s (Peer: %s, Data: %s)", s.cfg.AppName, s.cfg.ListenAddr, s.cfg.PeerOrigin, s.cfg.DataDir)
	return server.ListenAndServe()
}

// Storage returns the underlying storage instance (useful for testing).
func (s *Server) Storage() *Storage {
	return s.storage
}

// Config returns the server configuration.
func (s *Server) Config() Config {
	return s.cfg
}

// Auth returns the auth manager instance.
func (s *Server) Auth() *AuthManager {
	return s.auth
}

// -----------------------------------------------------------------------------
// Security Middleware
// -----------------------------------------------------------------------------

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strict security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Prevent browser from caching stale files from previous projects on this port
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		altPeer := loopbackAlt(s.cfg.PeerOrigin)

		// Content Security Policy (zero 'unsafe-inline' in script-src; strictly same-origin connect-src)
		var csp string
		if s.cfg.AllowEmbedding {
			// Permitted to be embedded by peer origin
			csp = fmt.Sprintf("frame-ancestors 'self' %s %s; default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'", s.cfg.PeerOrigin, altPeer)
		} else {
			// Host page embedding peer
			csp = fmt.Sprintf("frame-ancestors 'none'; default-src 'self'; frame-src 'self' %s %s; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'", s.cfg.PeerOrigin, altPeer)
		}
		w.Header().Set("Content-Security-Policy", csp)

		// No cross-origin CORS headers are emitted: UMAI frontends communicate with their
		// peer exclusively via browser MessagePort and only call their own origin's HTTP API.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// CSRF protection on state-changing requests (POST, PUT, DELETE, PATCH):
		// 1. If an Origin header is present, it must match this server's own origin.
		// 2. If Origin is omitted on a cookie-authenticated request (e.g. stripped Referrer/Origin),
		//    require an explicit custom header (X-UMAI-CSRF, X-UMAI-Session, or Authorization)
		//    which cross-site HTML <form enctype="multipart/form-data"> submissions cannot set.
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			if origin := r.Header.Get("Origin"); origin != "" {
				if !s.isSameServerOrigin(origin, r) {
					writeJSON(w, http.StatusForbidden, map[string]string{
						"error": "forbidden: cross-origin state-changing request rejected",
					})
					return
				}
			} else if r.Header.Get("Cookie") != "" &&
				r.Header.Get("X-UMAI-CSRF") == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "forbidden: missing Origin or X-UMAI-CSRF header on cookie-authenticated request",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isSameServerOrigin checks whether the HTTP Origin header matches this server's own host/listen address
// (allowing localhost <-> 127.0.0.1 loopback equivalence on the same port).
func (s *Server) isSameServerOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	reqHost := r.Host
	if reqHost == "" {
		reqHost = s.cfg.ListenAddr
	}
	if strings.EqualFold(u.Host, reqHost) || strings.EqualFold(u.Host, s.cfg.ListenAddr) {
		return true
	}
	altHost := loopbackAlt(reqHost)
	altListen := loopbackAlt(s.cfg.ListenAddr)
	return strings.EqualFold(u.Host, altHost) || strings.EqualFold(u.Host, altListen)
}

// requireAuth middleware ensures an active session exists.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := s.auth.GetSessionID(r)
		if _, ok := s.auth.ValidateSession(sessionID); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "unauthorized",
				"hint":  "Please log in to perform this operation",
			})
			return
		}
		next(w, r)
	}
}

// -----------------------------------------------------------------------------
// Route Registration
// -----------------------------------------------------------------------------

func (s *Server) registerRoutes() {
	// Status & Config
	s.mux.HandleFunc("GET /api/status", s.handleStatus)

	// Auth
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)

	// Documents
	s.mux.HandleFunc("GET /api/docs", s.requireAuth(s.handleListDocs))
	s.mux.HandleFunc("POST /api/docs", s.requireAuth(s.handleUploadDoc))
	s.mux.HandleFunc("GET /api/docs/{name}", s.requireAuth(s.handleDownloadDoc))
	s.mux.HandleFunc("DELETE /api/docs/{name}", s.requireAuth(s.handleDeleteDoc))

	// Outbox
	s.mux.HandleFunc("GET /api/outbox", s.requireAuth(s.handleListOutbox))
	s.mux.HandleFunc("POST /api/outbox", s.requireAuth(s.handleCreateOutbox))
	s.mux.HandleFunc("GET /api/outbox/{id}", s.requireAuth(s.handleGetOutboxMessage))
	s.mux.HandleFunc("GET /api/outbox/{id}/attachments/{filename}", s.requireAuth(s.handleGetOutboxAttachment))
	s.mux.HandleFunc("POST /api/outbox/ack", s.requireAuth(s.handleAckOutbox))

	// Inbox & Acceptance
	s.mux.HandleFunc("GET /api/inbox", s.requireAuth(s.handleListInbox))
	s.mux.HandleFunc("GET /api/inbox/{id}", s.requireAuth(s.handleGetInboxMessage))
	s.mux.HandleFunc("GET /api/inbox/{id}/attachments/{filename}", s.requireAuth(s.handleGetInboxAttachment))
	s.mux.HandleFunc("GET /api/accepted", s.requireAuth(s.handleListAccepted))
	s.mux.HandleFunc("GET /api/accepted/receipts", s.requireAuth(s.handleListAcceptedReceipts))
	s.mux.HandleFunc("POST /api/inbox", s.requireAuth(s.handleAcceptMessage))

	// Serve the common JavaScript library from /js/umai.js
	s.mux.HandleFunc("GET /js/umai.js", s.handleServeUmaiJS)

	// Static Assets & UI
	s.mux.Handle("/", s.fs)
}

// -----------------------------------------------------------------------------
// Handlers: Status & Auth
// -----------------------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	outboxIDs, _ := s.storage.ListOutboxIDs()
	inboxMsgs, _ := s.storage.ListInbox()
	acceptedIDs := s.storage.ListAccepted()

	sessionID := s.auth.GetSessionID(r)
	_, authenticated := s.auth.ValidateSession(sessionID)

	resp := map[string]any{
		"app_name":        s.cfg.AppName,
		"role":            s.cfg.Role,
		"listen_addr":     s.cfg.ListenAddr,
		"peer_origin":     s.cfg.PeerOrigin,
		"peer_embed_url":  s.cfg.PeerEmbedURL,
		"authenticated":   authenticated,
		"public_key":      s.storage.PublicKeyHex(),
		"peer_public_key": s.storage.PeerPublicKeyHex(),
		"outbox_count":    len(outboxIDs),
		"inbox_count":     len(inboxMsgs),
		"accepted_count":  len(acceptedIDs),
	}

	// Only expose message IDs when authenticated (prevents pre-emptive ID squatting)
	if authenticated {
		resp["outbox_ids"] = outboxIDs
		resp["accepted_ids"] = acceptedIDs
	}

	writeJSON(w, http.StatusOK, resp)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !isJSONContentType(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	sessionID, ok := s.auth.Authenticate(req.Username, req.Password)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}

	s.auth.SetSessionCookie(w, r, sessionID)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      req.Username,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := s.auth.GetSessionID(r)
	if sessionID != "" {
		s.auth.RevokeSession(sessionID)
	}
	s.auth.ClearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	sessionID := s.auth.GetSessionID(r)
	sess, ok := s.auth.ValidateSession(sessionID)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      sess.Username,
	})
}

// -----------------------------------------------------------------------------
// Handlers: Documents
// -----------------------------------------------------------------------------

func (s *Server) handleListDocs(w http.ResponseWriter, r *http.Request) {
	docs, err := s.storage.ListDocuments()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if docs == nil {
		docs = []DocumentInfo{}
	}
	writeJSON(w, http.StatusOK, docs)
}

func (s *Server) handleUploadDoc(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadSize+10*1024*1024)
	if err := r.ParseMultipartForm(s.cfg.MaxUploadSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to parse multipart form"})
		return
	}

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file uploaded"})
		return
	}
	if len(files) > MaxAttachmentsPerMessage {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrTooManyAttachments.Error()})
		return
	}

	var saved []DocumentInfo
	for _, fh := range files {
		f, err := fh.Open()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		doc, err := s.storage.SaveDocument(fh.Filename, f)
		_ = f.Close()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		saved = append(saved, *doc)
	}

	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleDownloadDoc(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	decodedName, err := url.PathUnescape(name)
	if err == nil && decodedName != "" {
		name = decodedName
	}

	path, err := s.storage.GetDocumentPath(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	http.ServeFile(w, r, path)
}

func (s *Server) handleDeleteDoc(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	decodedName, err := url.PathUnescape(name)
	if err == nil && decodedName != "" {
		name = decodedName
	}

	if err := s.storage.DeleteDocument(name); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// -----------------------------------------------------------------------------
// Handlers: Outbox
// -----------------------------------------------------------------------------

func (s *Server) handleListOutbox(w http.ResponseWriter, r *http.Request) {
	sessionID := s.auth.GetSessionID(r)
	msgs, err := s.storage.ListOutboxForSession(sessionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if msgs == nil {
		msgs = []*Message{}
	}
	writeJSON(w, http.StatusOK, msgs)
}

type createOutboxRequest struct {
	Payload   any      `json:"payload"`
	Documents []string `json:"documents"`
}

func (s *Server) handleCreateOutbox(w http.ResponseWriter, r *http.Request) {
	if !isJSONContentType(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	var req createOutboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	msg, err := s.storage.CreateOutboxMessage(req.Payload, req.Documents)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, msg)
}

func (s *Server) handleGetOutboxMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	msg, err := s.storage.GetOutboxMessage(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

func (s *Server) handleGetOutboxAttachment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	filename := r.PathValue("filename")
	decodedFile, err := url.PathUnescape(filename)
	if err == nil && decodedFile != "" {
		filename = decodedFile
	}

	path, err := s.storage.GetOutboxAttachmentPath(id, filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	http.ServeFile(w, r, path)
}

type ackRequest struct {
	IDs      []string          `json:"ids"`
	Receipts map[string]string `json:"receipts,omitempty"`
}

func (s *Server) handleAckOutbox(w http.ResponseWriter, r *http.Request) {
	if !isJSONContentType(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	var req ackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	if err := s.storage.AcknowledgeMessagesVerified(req.IDs, req.Receipts); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"acknowledged": true})
}

// -----------------------------------------------------------------------------
// Handlers: Inbox & Acceptance
// -----------------------------------------------------------------------------

func (s *Server) handleListInbox(w http.ResponseWriter, r *http.Request) {
	msgs, err := s.storage.ListInbox()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if msgs == nil {
		msgs = []*Message{}
	}
	writeJSON(w, http.StatusOK, msgs)
}

func (s *Server) handleGetInboxMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	msg, err := s.storage.GetInboxMessage(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

func (s *Server) handleGetInboxAttachment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	filename := r.PathValue("filename")
	decodedFile, err := url.PathUnescape(filename)
	if err == nil && decodedFile != "" {
		filename = decodedFile
	}

	path, err := s.storage.GetInboxAttachmentPath(id, filename)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	http.ServeFile(w, r, path)
}

func (s *Server) handleListAccepted(w http.ResponseWriter, r *http.Request) {
	accepted := s.storage.ListAccepted()
	if accepted == nil {
		accepted = []string{}
	}
	writeJSON(w, http.StatusOK, accepted)
}

func (s *Server) handleListAcceptedReceipts(w http.ResponseWriter, r *http.Request) {
	receipts := s.storage.ListAcceptedReceipts()
	writeJSON(w, http.StatusOK, receipts)
}

// handleAcceptMessage receives a PUT message transmitted from peer through browser.
// Multipart form contains:
// - "id": string message ID
// - "payload": JSON string of metadata
// - "signature": optional/expected Ed25519 signature hex of canonical PUT digest
// - "attachments": one or more binary files
func (s *Server) handleAcceptMessage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadSize+10*1024*1024)
	if err := r.ParseMultipartForm(s.cfg.MaxUploadSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed parsing multipart form"})
		return
	}

	msgID := r.FormValue("id")
	if msgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing message id"})
		return
	}

	signatureHex := r.FormValue("signature")

	// Payload JSON
	payloadStr := r.FormValue("payload")
	var payload any
	if payloadStr != "" {
		if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
			payload = payloadStr
		}
	}

	// Attachments
	var attReaders []AttachmentReader
	fileHeaders := r.MultipartForm.File["attachments"]
	if len(fileHeaders) > MaxAttachmentsPerMessage {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrTooManyAttachments.Error()})
		return
	}

	var openFiles []io.Closer
	defer func() {
		for _, f := range openFiles {
			_ = f.Close()
		}
	}()

	for _, fh := range fileHeaders {
		f, err := fh.Open()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		openFiles = append(openFiles, f)
		attReaders = append(attReaders, AttachmentReader{
			Name:   fh.Filename,
			Reader: f,
		})
	}

	msg, err := s.storage.AcceptSignedMessage(msgID, payload, attReaders, signatureHex)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":    true,
		"ack_receipt": msg.AckReceipt,
		"message":     msg,
	})
}

// -----------------------------------------------------------------------------
// Handlers: Serve UMAI Library
// -----------------------------------------------------------------------------

func (s *Server) handleServeUmaiJS(w http.ResponseWriter, r *http.Request) {
	// Look for js/umai.js relative to project root or binary
	paths := []string{
		"../../js/umai.js",
		"../js/umai.js",
		"./js/umai.js",
	}

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
	}

	http.NotFound(w, r)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func isJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json")
}

func loopbackAlt(origin string) string {
	if strings.Contains(origin, "127.0.0.1") {
		return strings.Replace(origin, "127.0.0.1", "localhost", 1)
	}
	if strings.Contains(origin, "localhost") {
		return strings.Replace(origin, "localhost", "127.0.0.1", 1)
	}
	return origin
}
