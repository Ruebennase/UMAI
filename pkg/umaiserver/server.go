package umaiserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

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
	storage, err := NewStorage(cfg.DataDir, cfg.MaxUploadSize)
	if err != nil {
		return nil, fmt.Errorf("initializing storage: %w", err)
	}

	auth := NewAuthManager(cfg.AuthUsername, cfg.AuthPassword)

	s := &Server{
		cfg:     cfg,
		storage: storage,
		auth:    auth,
		mux:     http.NewServeMux(),
		fs:      http.FileServer(http.Dir(staticDir)),
	}

	s.registerRoutes()
	return s, nil
}

// Handler returns the HTTP handler with global middleware.
func (s *Server) Handler() http.Handler {
	return s.securityMiddleware(s.mux)
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	server := &http.Server{
		Addr:    s.cfg.ListenAddr,
		Handler: s.Handler(),
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

		// Content Security Policy
		var csp string
		if s.cfg.AllowEmbedding {
			// Permitted to be embedded by peer origin
			csp = fmt.Sprintf("frame-ancestors 'self' %s; default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'", s.cfg.PeerOrigin)
		} else {
			// Host page embedding peer
			csp = fmt.Sprintf("frame-ancestors 'none'; default-src 'self'; frame-src 'self' %s; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'", s.cfg.PeerOrigin)
		}
		w.Header().Set("Content-Security-Policy", csp)

		// CORS: Restrictive, allow only local same-origin or explicit peer origin for specific endpoints
		origin := r.Header.Get("Origin")
		if origin != "" && (origin == s.cfg.PeerOrigin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-UMAI-Session")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
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

	writeJSON(w, http.StatusOK, map[string]any{
		"app_name":       s.cfg.AppName,
		"role":           s.cfg.Role,
		"listen_addr":    s.cfg.ListenAddr,
		"peer_origin":    s.cfg.PeerOrigin,
		"peer_embed_url": s.cfg.PeerEmbedURL,
		"authenticated":  authenticated,
		"outbox_count":   len(outboxIDs),
		"inbox_count":    len(inboxMsgs),
		"accepted_count": len(acceptedIDs),
		"outbox_ids":     outboxIDs,
		"accepted_ids":   acceptedIDs,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
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
		"session_id":    sessionID,
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
		"session_id":    sess.ID,
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
	if err := r.ParseMultipartForm(s.cfg.MaxUploadSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to parse multipart form"})
		return
	}

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file uploaded"})
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
	msgs, err := s.storage.ListOutbox()
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

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	http.ServeFile(w, r, path)
}

type ackRequest struct {
	IDs []string `json:"ids"`
}

func (s *Server) handleAckOutbox(w http.ResponseWriter, r *http.Request) {
	var req ackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	if err := s.storage.AcknowledgeMessages(req.IDs); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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

// handleAcceptMessage receives a PUT message transmitted from peer through browser.
// Multipart form contains:
// - "id": string message ID
// - "payload": JSON string of metadata
// - "attachments": one or more binary files
func (s *Server) handleAcceptMessage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(s.cfg.MaxUploadSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed parsing multipart form"})
		return
	}

	msgID := r.FormValue("id")
	if msgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing message id"})
		return
	}

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

	msg, err := s.storage.AcceptMessage(msgID, payload, attReaders)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": true,
		"message":  msg,
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
