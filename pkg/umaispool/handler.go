package umaispool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// MaxAttachmentMetaBytes bounds the explicit JSON attachment_meta field in multipart POST /inbox requests.
	MaxAttachmentMetaBytes = 64 * 1024

	// DefaultMultipartMemory (4 MiB) bounds the multipart parser's in-memory file buffering
	// (spilling larger uploaded file parts to temporary files cleaned up via MultipartForm.RemoveAll).
	// Note: this bounds only the multipart parser's file-part RAM threshold, not total HTTP request
	// or server memory; total request-size limits (MaxBytesReader) and concurrent activity still apply.
	DefaultMultipartMemory = 4 << 20

	// MultipartEnvelopeOverhead (10 MiB) bounds multipart framing, form fields, and JSON payload overhead
	// on top of Storage.MaxUploadSize() when wrapping incoming POST bodies in http.MaxBytesReader.
	MultipartEnvelopeOverhead = 10 << 20
)

// AttachmentMetaEntry declares explicit per-attachment metadata in multipart POST /inbox uploads,
// avoiding reliance on browser/HTTP multipart Content-Type defaults so absent media_type remains absent.
type AttachmentMetaEntry struct {
	Name      string `json:"name"`
	MediaType string `json:"media_type,omitempty"`
}

// Operation identifies the spool action being authorized by an Authorizer.
type Operation string

const (
	OpOutboxList       Operation = "outbox:list"
	OpOutboxRead       Operation = "outbox:read"
	OpOutboxAck        Operation = "outbox:ack"
	OpAcceptanceLookup Operation = "inbox:acceptance"
	OpInboxAccept      Operation = "inbox:accept"
	OpInboxRead        Operation = "inbox:read"
)

var (
	ErrUnauthorized      = errors.New("unauthorized")
	ErrForbidden         = errors.New("forbidden")
	ErrMissingAuthorizer = errors.New("spool handler requires a non-nil Authorizer")
	ErrMissingStorage    = errors.New("spool handler requires a non-nil Storage")
)

// Principal describes the authenticated caller approved by Authorizer.
type Principal struct {
	// Subject identifies the authenticated user or service principal.
	Subject string
	// SessionKey optionally identifies the caller's browser session so concurrent
	// sessions deterministically rotate unclaimed outbox messages.
	SessionKey string
}

// Authorizer authenticates and authorizes incoming HTTP requests for a given spool Operation.
// Returning ErrForbidden yields 403 Forbidden; any other non-nil error fails closed with 401 Unauthorized.
type Authorizer func(r *http.Request, op Operation) (Principal, error)

// HandlerConfig configures a reusable HTTP spool Handler.
type HandlerConfig struct {
	// Storage is the underlying spool storage instance (required).
	Storage *Storage
	// Authorizer gates every spool endpoint before touching Storage or parsing multipart uploads (required).
	Authorizer Authorizer
	// RoutePrefix is the URL path prefix for spool endpoints.
	// Empty defaults to "/api"; use "/" to mount at the root path ("/outbox", "/inbox", etc.).
	RoutePrefix string
	// ListenAddr optionally specifies the server's configured host:port for same-origin Origin validation.
	ListenAddr string
	// AllowedServerOrigins optionally lists explicit server origins (e.g. "https://app.example.com")
	// accepted by same-origin CSRF validation when behind a reverse proxy.
	AllowedServerOrigins []string
	// AllowUnsigned explicitly opts into unsigned operation when Storage has no SigningConfig.
	// When false (default), NewHandler fails closed if Storage.HasSigningConfig() is false.
	AllowUnsigned bool
}

// Handler exposes the standard UMAI spool HTTP endpoints backed by Storage.
type Handler struct {
	storage       *Storage
	authorizer    Authorizer
	routePrefix   string
	listenAddr    string
	allowedOrigin []string
	allowUnsigned bool
	mux           *http.ServeMux
}

// NewHandler validates configuration (failing closed if Storage, Authorizer, or SigningConfig is missing)
// and returns a ready-to-mount HTTP spool Handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if cfg.Storage == nil {
		return nil, ErrMissingStorage
	}
	if cfg.Authorizer == nil {
		return nil, ErrMissingAuthorizer
	}
	if !cfg.AllowUnsigned && !cfg.Storage.HasSigningConfig() {
		return nil, ErrSigningNotConfigured
	}

	prefix := normalizeRoutePrefix(cfg.RoutePrefix)

	var allowed []string
	for _, raw := range cfg.AllowedServerOrigins {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" {
			allowed = append(allowed, trimmed)
		}
	}

	h := &Handler{
		storage:       cfg.Storage,
		authorizer:    cfg.Authorizer,
		routePrefix:   prefix,
		listenAddr:    strings.TrimSpace(cfg.ListenAddr),
		allowedOrigin: allowed,
		allowUnsigned: cfg.AllowUnsigned,
		mux:           http.NewServeMux(),
	}
	h.RegisterRoutes(h.mux)
	return h, nil
}

func normalizeRoutePrefix(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/api"
	}
	if trimmed == "/" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return strings.TrimRight(trimmed, "/")
}

// RoutePrefix returns the normalized route prefix (e.g. "/api" or "" when mounted at "/").
func (h *Handler) RoutePrefix() string {
	return h.routePrefix
}

// ServeHTTP dispatches requests through the spool handler's internal router.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	applyBaseSecurityHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.mux.ServeHTTP(w, r)
}

// RegisterRoutes mounts all UMAI spool endpoints onto mux under h.RoutePrefix().
// Every registered endpoint enforces security headers, same-origin/CSRF checks, and h.Authorizer.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	p := h.routePrefix

	// Outbox endpoints
	mux.HandleFunc("GET "+p+"/outbox", h.guard(OpOutboxList, h.handleListOutbox))
	mux.HandleFunc("GET "+p+"/outbox/{id}", h.guard(OpOutboxRead, h.handleGetOutboxMessage))
	mux.HandleFunc("GET "+p+"/outbox/{id}/attachments/{filename}", h.guard(OpOutboxRead, h.handleGetOutboxAttachment))
	mux.HandleFunc("POST "+p+"/outbox/ack", h.guard(OpOutboxAck, h.handleAckOutbox))

	// Inbox & acceptance endpoints
	mux.HandleFunc("GET "+p+"/inbox", h.guard(OpInboxRead, h.handleListInbox))
	mux.HandleFunc("GET "+p+"/inbox/{id}", h.guard(OpInboxRead, h.handleGetInboxMessage))
	mux.HandleFunc("GET "+p+"/inbox/{id}/attachments/{filename}", h.guard(OpInboxRead, h.handleGetInboxAttachment))
	mux.HandleFunc("POST "+p+"/inbox/acceptance", h.guard(OpAcceptanceLookup, h.handleGetAcceptance))
	mux.HandleFunc("GET "+p+"/accepted", h.guard(OpInboxRead, h.handleListAccepted))
	mux.HandleFunc("GET "+p+"/accepted/receipts", h.guard(OpInboxRead, h.handleListAcceptedReceipts))
	mux.HandleFunc("POST "+p+"/inbox", h.guard(OpInboxAccept, h.handleAcceptMessage))
}

func applyBaseSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if w.Header().Get("Content-Security-Policy") == "" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	}
}

func (h *Handler) guard(op Operation, fn func(w http.ResponseWriter, r *http.Request, principal Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		applyBaseSecurityHeaders(w)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// CSRF protection on state-changing requests (POST, PUT, DELETE, PATCH):
		// 1. If Origin is present, it must match this server's own origin.
		// 2. If Origin is omitted on a cookie-bearing request, require X-UMAI-CSRF.
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			if origin := r.Header.Get("Origin"); origin != "" {
				if !h.isSameServerOrigin(origin, r) {
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

		if h.authorizer == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		principal, authErr := h.authorizer(r, op)
		if authErr != nil {
			if errors.Is(authErr, ErrForbidden) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		fn(w, r, principal)
	}
}

func (h *Handler) isSameServerOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}

	for _, allowed := range h.allowedOrigin {
		au, aErr := url.Parse(allowed)
		if aErr == nil && au.Host != "" && strings.EqualFold(u.Scheme, au.Scheme) && strings.EqualFold(u.Host, au.Host) {
			return true
		}
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
		reqHost = h.listenAddr
	}
	if reqHost != "" && strings.EqualFold(u.Host, reqHost) {
		return true
	}
	if h.listenAddr != "" && strings.EqualFold(u.Host, h.listenAddr) {
		return true
	}
	if reqHost != "" {
		if altHost, ok := swapLoopbackHost(reqHost); ok && strings.EqualFold(u.Host, altHost) {
			return true
		}
	}
	if h.listenAddr != "" {
		if altListen, ok := swapLoopbackHost(h.listenAddr); ok && strings.EqualFold(u.Host, altListen) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Outbox Route Handlers
// -----------------------------------------------------------------------------

func (h *Handler) handleListOutbox(w http.ResponseWriter, r *http.Request, principal Principal) {
	msgs, err := h.storage.ListOutboxForSession(principal.SessionKey)
	if err != nil {
		writeSpoolError(w, err)
		return
	}
	if msgs == nil {
		msgs = []*Message{}
	}
	writeJSON(w, http.StatusOK, msgs)
}

func (h *Handler) handleGetOutboxMessage(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("id")
	msg, err := h.storage.GetOutboxMessage(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeSpoolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

func (h *Handler) handleGetOutboxAttachment(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("id")
	filename := r.PathValue("filename")
	if decodedFile, err := url.PathUnescape(filename); err == nil && decodedFile != "" {
		filename = decodedFile
	}

	path, err := h.storage.GetOutboxAttachmentPath(id, filename)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeSpoolError(w, err)
		return
	}

	serveBinaryAttachment(w, r, path)
}

type ackRequest struct {
	IDs      []string          `json:"ids"`
	Receipts map[string]string `json:"receipts,omitempty"`
}

func (h *Handler) handleAckOutbox(w http.ResponseWriter, r *http.Request, _ Principal) {
	if !isJSONContentType(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
	var req ackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isMaxBytesError(err) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body exceeds maximum allowed size"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}
	if len(req.IDs) > MaxBatchIDs {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrTooManyIDs.Error()})
		return
	}

	var err error
	if h.storage.HasSigningConfig() || !h.allowUnsigned {
		err = h.storage.AcknowledgeMessagesVerified(req.IDs, req.Receipts)
	} else {
		err = h.storage.AcknowledgeMessages(req.IDs)
	}
	if err != nil {
		writeSpoolError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"acknowledged": true})
}

// -----------------------------------------------------------------------------
// Inbox & Acceptance Route Handlers
// -----------------------------------------------------------------------------

func (h *Handler) handleListInbox(w http.ResponseWriter, r *http.Request, _ Principal) {
	msgs, err := h.storage.ListInbox()
	if err != nil {
		writeSpoolError(w, err)
		return
	}
	if msgs == nil {
		msgs = []*Message{}
	}
	writeJSON(w, http.StatusOK, msgs)
}

func (h *Handler) handleGetInboxMessage(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("id")
	msg, err := h.storage.GetInboxMessage(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeSpoolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

func (h *Handler) handleGetInboxAttachment(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("id")
	filename := r.PathValue("filename")
	if decodedFile, err := url.PathUnescape(filename); err == nil && decodedFile != "" {
		filename = decodedFile
	}

	path, err := h.storage.GetInboxAttachmentPath(id, filename)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		writeSpoolError(w, err)
		return
	}

	serveBinaryAttachment(w, r, path)
}

func (h *Handler) handleGetAcceptance(w http.ResponseWriter, r *http.Request, _ Principal) {
	if !isJSONContentType(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDs == nil {
		if isMaxBytesError(err) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body exceeds maximum allowed size"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body; expected {\"ids\": [...]}"})
		return
	}

	results, err := h.storage.GetAcceptance(req.IDs)
	if err != nil {
		writeSpoolError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
	})
}

func (h *Handler) handleListAccepted(w http.ResponseWriter, _ *http.Request, _ Principal) {
	accepted := h.storage.ListAccepted()
	if accepted == nil {
		accepted = []string{}
	}
	writeJSON(w, http.StatusOK, accepted)
}

func (h *Handler) handleListAcceptedReceipts(w http.ResponseWriter, _ *http.Request, _ Principal) {
	receipts := h.storage.ListAcceptedReceipts()
	writeJSON(w, http.StatusOK, receipts)
}

func (h *Handler) handleAcceptMessage(w http.ResponseWriter, r *http.Request, _ Principal) {
	maxUpload := h.storage.MaxUploadSize()
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+MultipartEnvelopeOverhead)
	if err := r.ParseMultipartForm(DefaultMultipartMemory); err != nil {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
		if isMaxBytesError(err) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": ErrFileTooLarge.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed parsing multipart form"})
		return
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}

	msgID := r.FormValue("id")
	if msgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing message id"})
		return
	}

	signatureHex := r.FormValue("signature")

	payloadStr := r.FormValue("payload")
	var payload any
	if payloadStr != "" {
		dec := json.NewDecoder(strings.NewReader(payloadStr))
		dec.UseNumber()
		if err := dec.Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload JSON"})
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "trailing data in payload JSON"})
			return
		}
	}

	fileHeaders := r.MultipartForm.File["attachments"]
	if len(fileHeaders) > MaxAttachmentsPerMessage {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrTooManyAttachments.Error()})
		return
	}

	metaByName, err := parseAndValidateAttachmentMeta(r.MultipartForm.Value["attachment_meta"], len(fileHeaders))
	if err != nil {
		writeSpoolError(w, err)
		return
	}

	attReaders := make([]AttachmentReader, 0, len(fileHeaders))
	var openFiles []io.Closer
	defer func() {
		for _, f := range openFiles {
			_ = f.Close()
		}
	}()

	seenUploads := make(map[string]bool, len(fileHeaders))
	for _, fh := range fileHeaders {
		cleanFileName, err := SanitizeFilename(fh.Filename)
		if err != nil {
			writeSpoolError(w, err)
			return
		}
		if seenUploads[cleanFileName] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrDuplicateAttachment.Error()})
			return
		}
		seenUploads[cleanFileName] = true

		declaredMedia, ok := metaByName[cleanFileName]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrInvalidAttachmentMeta.Error()})
			return
		}

		f, err := fh.Open()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal storage error"})
			return
		}
		openFiles = append(openFiles, f)
		attReaders = append(attReaders, AttachmentReader{
			Name:      cleanFileName,
			MediaType: declaredMedia,
			Reader:    f,
		})
	}

	var msg *Message
	if h.storage.HasSigningConfig() || !h.allowUnsigned {
		msg, err = h.storage.AcceptSignedMessage(msgID, payload, attReaders, signatureHex)
	} else {
		msg, err = h.storage.AcceptMessage(msgID, payload, attReaders)
	}
	if err != nil {
		writeSpoolError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accepted":    true,
		"accepted_at": msg.AcceptedAt,
		"ack_receipt": msg.AckReceipt,
		"message":     msg,
	})
}

func parseAndValidateAttachmentMeta(rawValues []string, expectedCount int) (map[string]string, error) {
	if len(rawValues) > 1 {
		return nil, ErrInvalidAttachmentMeta
	}
	if len(rawValues) == 0 || strings.TrimSpace(rawValues[0]) == "" {
		if expectedCount == 0 {
			return map[string]string{}, nil
		}
		return nil, ErrInvalidAttachmentMeta
	}

	raw := rawValues[0]
	if len(raw) > MaxAttachmentMetaBytes {
		return nil, ErrInvalidAttachmentMeta
	}

	var entries []AttachmentMetaEntry
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil || entries == nil {
		return nil, ErrInvalidAttachmentMeta
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, ErrInvalidAttachmentMeta
	}

	if len(entries) > MaxAttachmentsPerMessage || len(entries) != expectedCount {
		return nil, ErrInvalidAttachmentMeta
	}

	metaByName := make(map[string]string, len(entries))
	for _, entry := range entries {
		cleanName, err := SanitizeFilename(entry.Name)
		if err != nil {
			return nil, ErrInvalidAttachmentMeta
		}
		if _, dup := metaByName[cleanName]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
		}
		cleanMedia, err := ValidateMediaType(entry.MediaType)
		if err != nil {
			return nil, err
		}
		metaByName[cleanName] = cleanMedia
	}
	return metaByName, nil
}

// -----------------------------------------------------------------------------
// Static Client Script Helper
// -----------------------------------------------------------------------------

// ServeClientScripts registers GET /js/umai.js and GET /js/umai-spool.js on mux.
// If jsDir is empty, it searches standard relative locations and the repository's js/ directory.
func ServeClientScripts(mux *http.ServeMux, jsDir string) {
	mux.HandleFunc("GET /js/umai.js", func(w http.ResponseWriter, r *http.Request) {
		serveJSFile(w, r, jsDir, "umai.js")
	})
	mux.HandleFunc("GET /js/umai-spool.js", func(w http.ResponseWriter, r *http.Request) {
		serveJSFile(w, r, jsDir, "umai-spool.js")
	})
}

func serveJSFile(w http.ResponseWriter, r *http.Request, jsDir string, filename string) {
	var candidates []string
	if strings.TrimSpace(jsDir) != "" {
		candidates = append(candidates, filepath.Join(jsDir, filename))
	}
	candidates = append(candidates,
		filepath.Join("./js", filename),
		filepath.Join("../js", filename),
		filepath.Join("../../js", filename),
	)
	if _, callerFile, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, filepath.Join(filepath.Dir(callerFile), "..", "..", "js", filename))
	}

	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
	}
	http.NotFound(w, r)
}

// -----------------------------------------------------------------------------
// Internal HTTP Helpers
// -----------------------------------------------------------------------------

func serveBinaryAttachment(w http.ResponseWriter, r *http.Request, path string) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
	http.ServeFile(w, r, path)
}

func isMaxBytesError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return err != nil && errors.As(err, &maxBytesErr)
}

// HTTPStatusForError maps spool domain, limit, conflict, and storage/durability errors to HTTP status codes.
func HTTPStatusForError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if isMaxBytesError(err) || errors.Is(err, ErrFileTooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	if errors.Is(err, ErrNotFound) {
		return http.StatusNotFound
	}
	if errors.Is(err, ErrConflictingDuplicate) ||
		errors.Is(err, ErrStorageCollision) ||
		errors.Is(err, ErrAlreadyPublished) {
		return http.StatusConflict
	}
	if errors.Is(err, ErrInvalidID) ||
		errors.Is(err, ErrTraversal) ||
		errors.Is(err, ErrDuplicateAttachment) ||
		errors.Is(err, ErrTooManyAttachments) ||
		errors.Is(err, ErrTooManyIDs) ||
		errors.Is(err, ErrInvalidMediaType) ||
		errors.Is(err, ErrInvalidAttachmentMeta) ||
		errors.Is(err, ErrInvalidSignature) ||
		errors.Is(err, ErrInvalidReceipt) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func writeSpoolError(w http.ResponseWriter, err error) {
	status := HTTPStatusForError(err)
	if status == http.StatusInternalServerError {
		writeJSON(w, status, map[string]string{"error": "internal storage error"})
		return
	}
	if status == http.StatusRequestEntityTooLarge {
		writeJSON(w, status, map[string]string{"error": ErrFileTooLarge.Error()})
		return
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func isJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json")
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
