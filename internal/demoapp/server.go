package demoapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/umai-protocol/umai/pkg/umaispool"
)

func init() {
	_ = mime.AddExtensionType(".css", "text/css; charset=utf-8")
	_ = mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
	_ = mime.AddExtensionType(".html", "text/html; charset=utf-8")
	_ = mime.AddExtensionType(".json", "application/json; charset=utf-8")
}

// Server coordinates the demo application UI, demo login sessions, sample documents,
// and the reusable pkg/umaispool HTTP spool handler.
type Server struct {
	cfg     Config
	storage *umaispool.Storage
	spool   *umaispool.Handler
	docs    *DocStore
	auth    *AuthManager
	mux     *http.ServeMux
	fs      http.Handler
}

// NewServer initializes a demo UMAI server mounted over reusable pkg/umaispool components.
func NewServer(cfg Config, staticDir string) (*Server, error) {
	if cfg.PeerOrigin != "" {
		u, err := url.Parse(cfg.PeerOrigin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid peer origin %q: must be an http:// or https:// origin", cfg.PeerOrigin)
		}
	}

	isLocalOnly := isLoopbackHostPort(cfg.ListenAddr) &&
		isLoopbackOriginURL(cfg.PeerOrigin) &&
		isLoopbackOriginURL(cfg.PeerEmbedURL)

	usingDemoKeys := strings.TrimSpace(cfg.SigningPrivateKey) == "" || strings.TrimSpace(cfg.PeerPublicKey) == ""
	usingDemoPassword := cfg.AuthPassword == "" || cfg.AuthPassword == "umai123"

	if !cfg.AllowDemoDefaults {
		if usingDemoKeys {
			return nil, fmt.Errorf("production mode refuses built-in demo Ed25519 keys (addr=%q): set UMAI_SIGNING_PRIVATE_KEY and UMAI_PEER_PUBLIC_KEY, or pass -demo for local evaluation", cfg.ListenAddr)
		}
		if usingDemoPassword {
			return nil, fmt.Errorf("production mode refuses default demo password (addr=%q): set -pass / UMAI_AUTH_PASS, or pass -demo for local evaluation", cfg.ListenAddr)
		}
	} else if !isLocalOnly {
		if usingDemoKeys {
			return nil, fmt.Errorf("refusing to use deterministic demo Ed25519 keys for non-loopback deployment (addr=%q, peer=%q): set UMAI_SIGNING_PRIVATE_KEY and UMAI_PEER_PUBLIC_KEY", cfg.ListenAddr, cfg.PeerOrigin)
		}
		if usingDemoPassword {
			return nil, fmt.Errorf("refusing to use default demo password for non-loopback deployment (addr=%q, peer=%q): set -pass / UMAI_AUTH_PASS", cfg.ListenAddr, cfg.PeerOrigin)
		}
	}

	if staticDir != "" && cfg.DataDir != "" {
		absStatic, err1 := filepath.Abs(staticDir)
		absData, err2 := filepath.Abs(cfg.DataDir)
		if err1 == nil && err2 == nil {
			cleanStatic := filepath.Clean(absStatic)
			cleanData := filepath.Clean(absData)
			sep := string(filepath.Separator)
			if cleanStatic == cleanData ||
				strings.HasPrefix(cleanData, cleanStatic+sep) ||
				strings.HasPrefix(cleanStatic, cleanData+sep) {
				return nil, fmt.Errorf("security violation: static directory (%s) and data directory (%s) must not overlap", cleanStatic, cleanData)
			}
		}
	}

	storage, err := umaispool.NewStorage(cfg.DataDir, cfg.MaxUploadSize)
	if err != nil {
		return nil, fmt.Errorf("initializing spool storage: %w", err)
	}

	sigCfg, err := ResolveDemoSigningConfig(cfg.Role, cfg.PeerRole, cfg.SigningPrivateKey, cfg.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("initializing signing keys: %w", err)
	}
	if err := storage.SetSigningConfig(sigCfg); err != nil {
		return nil, fmt.Errorf("configuring spool signing: %w", err)
	}

	docs, err := NewDocStore(cfg.DataDir, cfg.MaxUploadSize)
	if err != nil {
		return nil, fmt.Errorf("initializing document store: %w", err)
	}

	auth := NewAuthManager(cfg.CookieName, cfg.AuthUsername, cfg.AuthPassword)

	spoolHandler, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:     storage,
		RoutePrefix: "/api",
		ListenAddr:  cfg.ListenAddr,
		Authorizer: func(r *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
			sessionID := auth.GetSessionID(r)
			sess, ok := auth.ValidateSession(sessionID)
			if !ok {
				return umaispool.Principal{}, umaispool.ErrUnauthorized
			}
			return umaispool.Principal{
				Subject:    sess.Username,
				SessionKey: sessionID,
			}, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("initializing spool HTTP handler: %w", err)
	}

	s := &Server{
		cfg:     cfg,
		storage: storage,
		spool:   spoolHandler,
		docs:    docs,
		auth:    auth,
		mux:     http.NewServeMux(),
		fs:      newStaticFileHandler(staticDir),
	}

	s.registerRoutes()
	return s, nil
}

func isLoopbackOriginURL(rawURL string) bool {
	if strings.TrimSpace(rawURL) == "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return isLoopbackHostPort(u.Host)
}

func newStaticFileHandler(staticDir string) http.Handler {
	fileServer := http.FileServer(http.Dir(staticDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for _, seg := range strings.Split(path, "/") {
			if strings.HasPrefix(seg, ".") && seg != "" {
				http.NotFound(w, r)
				return
			}
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case "", ".html", ".css", ".js", ".svg", ".png", ".ico", ".woff2", ".txt", ".map":
			// Allowed static web asset extensions
		default:
			http.NotFound(w, r)
			return
		}
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

// Handler returns the HTTP handler wrapped with the demo application's CSP & CSRF middleware.
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
		MaxHeaderBytes:    1 << 20,
	}
	if s.cfg.SigningPrivateKey == "" || s.cfg.PeerPublicKey == "" {
		log.Printf("[%s] SECURITY NOTICE: Using deterministic demo Ed25519 keys. Set UMAI_SIGNING_PRIVATE_KEY and UMAI_PEER_PUBLIC_KEY in production.", s.cfg.AppName)
	}
	if s.cfg.AuthPassword == "umai123" {
		log.Printf("[%s] SECURITY NOTICE: Using default demo credentials (%s / umai123). Override via -user/-pass or UMAI_AUTH_USER/UMAI_AUTH_PASS.", s.cfg.AppName, s.cfg.AuthUsername)
	}
	log.Printf("[%s] Starting on http://%s (Peer: %s, Data: %s)", s.cfg.AppName, s.cfg.ListenAddr, s.cfg.PeerOrigin, s.cfg.DataDir)
	return server.ListenAndServe()
}

// Storage returns the underlying reusable spool storage instance.
func (s *Server) Storage() *umaispool.Storage {
	return s.storage
}

// Docs returns the demo document store.
func (s *Server) Docs() *DocStore {
	return s.docs
}

// Config returns the demo server configuration.
func (s *Server) Config() Config {
	return s.cfg
}

// Auth returns the demo authentication manager.
func (s *Server) Auth() *AuthManager {
	return s.auth
}

// CreateOutboxFromDocs snapshots the named documents from s.Docs() into an immutable
// outbox message in s.Storage().
func (s *Server) CreateOutboxFromDocs(payload any, docNames []string) (*umaispool.Message, error) {
	if len(docNames) > umaispool.MaxAttachmentsPerMessage {
		return nil, umaispool.ErrTooManyAttachments
	}

	readers := make([]umaispool.AttachmentReader, 0, len(docNames))
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()

	for _, docName := range docNames {
		cleanName, err := umaispool.SanitizeFilename(docName)
		if err != nil {
			return nil, err
		}
		docPath, err := s.docs.GetDocumentPath(cleanName)
		if err != nil {
			return nil, fmt.Errorf("attachment document %s not found: %w", cleanName, err)
		}
		f, err := os.Open(docPath)
		if err != nil {
			return nil, err
		}
		closers = append(closers, f)
		readers = append(readers, umaispool.AttachmentReader{
			Name:   cleanName,
			Reader: f,
		})
	}

	return s.storage.CreateOutboxMessage(payload, readers)
}

// -----------------------------------------------------------------------------
// Demo Application Security Middleware
// -----------------------------------------------------------------------------

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		peerCSPSources := s.cfg.PeerOrigin
		if altPeer := loopbackAlt(s.cfg.PeerOrigin); altPeer != "" && altPeer != s.cfg.PeerOrigin {
			peerCSPSources = s.cfg.PeerOrigin + " " + altPeer
		}

		var csp string
		if s.cfg.AllowEmbedding {
			csp = fmt.Sprintf("frame-ancestors 'self' %s; default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'", peerCSPSources)
		} else {
			csp = fmt.Sprintf("frame-ancestors 'none'; default-src 'self'; frame-src 'self' %s; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'", peerCSPSources)
		}
		w.Header().Set("Content-Security-Policy", csp)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			if origin := r.Header.Get("Origin"); origin != "" {
				if !s.isSameServerOrigin(origin, r) {
					writeJSON(w, http.StatusForbidden, map[string]string{
						"error": "forbidden: cross-origin state-changing request rejected",
					})
					return
				}
			} else if r.Header.Get("Cookie") != "" && r.Header.Get("X-UMAI-CSRF") == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "forbidden: missing Origin or X-UMAI-CSRF header on cookie-authenticated request",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) isSameServerOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	expectedScheme := "http"
	if isHTTPSRequest(r) {
		expectedScheme = "https"
	}
	if !strings.EqualFold(u.Scheme, expectedScheme) {
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
	// Demo Status & Auth
	s.mux.HandleFunc("GET /api/status", s.handleStatus)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)

	// Demo Document Workspace
	s.mux.HandleFunc("GET /api/docs", s.requireAuth(s.handleListDocs))
	s.mux.HandleFunc("POST /api/docs", s.requireAuth(s.handleUploadDoc))
	s.mux.HandleFunc("GET /api/docs/{name}", s.requireAuth(s.handleDownloadDoc))
	s.mux.HandleFunc("DELETE /api/docs/{name}", s.requireAuth(s.handleDeleteDoc))

	// Demo Outbox Composition (snapshots local docs into reusable spool)
	s.mux.HandleFunc("POST /api/outbox", s.requireAuth(s.handleCreateOutbox))

	// Reusable UMAI Spool Endpoints (/api/outbox, /api/outbox/{id}, /api/outbox/ack, /api/inbox, /api/inbox/acceptance, etc.)
	s.spool.RegisterRoutes(s.mux)

	// Reusable UMAI Browser Scripts (/js/umai.js and /js/umai-spool.js)
	umaispool.ServeClientScripts(s.mux, "")

	// Static Assets & Demo UI
	s.mux.Handle("/", s.fs)
}

// -----------------------------------------------------------------------------
// Demo Handlers: Status, Auth, Documents, Outbox Composition
// -----------------------------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	outboxIDs, _ := s.storage.ListOutboxIDs()
	inboxMsgs, _ := s.storage.ListInbox()
	acceptedIDs := s.storage.ListAccepted()

	sessionID := s.auth.GetSessionID(r)
	_, authenticated := s.auth.ValidateSession(sessionID)

	resp := map[string]any{
		"app_name":        s.cfg.AppName,
		"role":            s.storage.LocalIdentity(),
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
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"username":      sess.Username,
	})
}

func (s *Server) handleListDocs(w http.ResponseWriter, _ *http.Request) {
	docs, err := s.docs.ListDocuments()
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
	maxUpload := s.cfg.MaxUploadSize
	if maxUpload <= 0 {
		maxUpload = umaispool.DefaultMaxUploadSize
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+umaispool.MultipartEnvelopeOverhead)
	if err := r.ParseMultipartForm(umaispool.DefaultMultipartMemory); err != nil {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
		if umaispool.HTTPStatusForError(err) == http.StatusRequestEntityTooLarge {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": umaispool.ErrFileTooLarge.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to parse multipart form"})
		return
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file uploaded"})
		return
	}
	if len(files) > umaispool.MaxAttachmentsPerMessage {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": umaispool.ErrTooManyAttachments.Error()})
		return
	}

	var saved []DocumentInfo
	for _, fh := range files {
		f, err := fh.Open()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal storage error"})
			return
		}
		doc, err := s.docs.SaveDocument(fh.Filename, f)
		_ = f.Close()
		if err != nil {
			status := umaispool.HTTPStatusForError(err)
			if status == http.StatusInternalServerError {
				writeJSON(w, status, map[string]string{"error": "internal storage error"})
				return
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		saved = append(saved, *doc)
	}

	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleDownloadDoc(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if decodedName, err := url.PathUnescape(name); err == nil && decodedName != "" {
		name = decodedName
	}

	path, err := s.docs.GetDocumentPath(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	http.ServeFile(w, r, path)
}

func (s *Server) handleDeleteDoc(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if decodedName, err := url.PathUnescape(name); err == nil && decodedName != "" {
		name = decodedName
	}

	if err := s.docs.DeleteDocument(name); err != nil {
		if errors.Is(err, umaispool.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
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
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		if umaispool.HTTPStatusForError(err) == http.StatusRequestEntityTooLarge {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body exceeds maximum allowed size"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	msg, err := s.CreateOutboxFromDocs(req.Payload, req.Documents)
	if err != nil {
		status := umaispool.HTTPStatusForError(err)
		if status == http.StatusInternalServerError {
			writeJSON(w, status, map[string]string{"error": "internal storage error"})
			return
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, msg)
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

func swapLoopbackHost(hostPort string) (string, bool) {
	if host, port, err := net.SplitHostPort(hostPort); err == nil {
		switch strings.ToLower(host) {
		case "127.0.0.1":
			return net.JoinHostPort("localhost", port), true
		case "localhost":
			return net.JoinHostPort("127.0.0.1", port), true
		default:
			return hostPort, false
		}
	}
	switch strings.ToLower(hostPort) {
	case "127.0.0.1":
		return "localhost", true
	case "localhost":
		return "127.0.0.1", true
	default:
		return hostPort, false
	}
}

func loopbackAlt(raw string) string {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return raw
		}
		swapped, ok := swapLoopbackHost(u.Host)
		if !ok {
			return raw
		}
		u.Host = swapped
		return u.String()
	}
	swapped, _ := swapLoopbackHost(raw)
	return swapped
}
