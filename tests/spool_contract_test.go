package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/umai-protocol/umai/pkg/umaispool"
)

func TestSpoolHandler_FailClosedInitializationAndCrypto(t *testing.T) {
	store, err := umaispool.NewStorage(t.TempDir(), 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}

	// 1. ParseSigningKeys must never fall back to demo keys
	if _, _, _, err := umaispool.ParseSigningKeys("", ""); !errors.Is(err, umaispool.ErrSigningNotConfigured) {
		t.Fatalf("Expected ErrSigningNotConfigured from ParseSigningKeys on empty keys, got %v", err)
	}

	// 2. AcceptSignedMessage and AcknowledgeMessagesVerified must fail closed when unconfigured
	if _, err := store.AcceptSignedMessage("msg-1", map[string]string{"a": "b"}, nil, "00"); !errors.Is(err, umaispool.ErrSigningNotConfigured) {
		t.Fatalf("Expected AcceptSignedMessage to fail closed with ErrSigningNotConfigured, got %v", err)
	}
	if err := store.AcknowledgeMessagesVerified([]string{"msg-1"}, map[string]string{"msg-1": "00"}); !errors.Is(err, umaispool.ErrSigningNotConfigured) {
		t.Fatalf("Expected AcknowledgeMessagesVerified to fail closed with ErrSigningNotConfigured, got %v", err)
	}

	// 3. SetSigningConfig must reject empty, padded, or identical identities
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "",
		PeerIdentity:  "peer-b",
		PrivateKey:    privA,
		PeerPublicKey: pubB,
	}); !errors.Is(err, umaispool.ErrMissingIdentity) {
		t.Fatalf("Expected ErrMissingIdentity for empty LocalIdentity, got %v", err)
	}
	if err := store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "same-peer",
		PeerIdentity:  "same-peer",
		PrivateKey:    privA,
		PeerPublicKey: pubB,
	}); !errors.Is(err, umaispool.ErrInvalidIdentity) {
		t.Fatalf("Expected ErrInvalidIdentity when LocalIdentity == PeerIdentity, got %v", err)
	}
	if err := store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: " padded ",
		PeerIdentity:  "peer-b",
		PrivateKey:    privA,
		PeerPublicKey: pubB,
	}); !errors.Is(err, umaispool.ErrInvalidIdentity) {
		t.Fatalf("Expected ErrInvalidIdentity for whitespace-padded identity, got %v", err)
	}
	_ = pubA

	// 4. NewHandler must fail closed when Storage, Authorizer, or SigningConfig is missing
	noopAuth := func(_ *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
		return umaispool.Principal{Subject: "u1"}, nil
	}
	if _, err := umaispool.NewHandler(umaispool.HandlerConfig{Authorizer: noopAuth}); !errors.Is(err, umaispool.ErrMissingStorage) {
		t.Fatalf("Expected ErrMissingStorage when Storage is nil, got %v", err)
	}
	if _, err := umaispool.NewHandler(umaispool.HandlerConfig{Storage: store, AllowUnsigned: true}); !errors.Is(err, umaispool.ErrMissingAuthorizer) {
		t.Fatalf("Expected ErrMissingAuthorizer when Authorizer is nil, got %v", err)
	}
	if _, err := umaispool.NewHandler(umaispool.HandlerConfig{Storage: store, Authorizer: noopAuth}); !errors.Is(err, umaispool.ErrSigningNotConfigured) {
		t.Fatalf("Expected ErrSigningNotConfigured when AllowUnsigned is false and SigningConfig is unset, got %v", err)
	}
}

func TestSpoolHandler_AuthorizerGating_And_SessionRotation(t *testing.T) {
	store, err := umaispool.NewStorage(t.TempDir(), 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	_, privLocal, _ := ed25519.GenerateKey(rand.Reader)
	pubPeer, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "service-alpha",
		PeerIdentity:  "service-beta",
		PrivateKey:    privLocal,
		PeerPublicKey: pubPeer,
	}); err != nil {
		t.Fatalf("SetSigningConfig: %v", err)
	}

	// Populate multiple outbox messages so we can also test SessionKey rotation
	for _, id := range []string{"msg-rot-1", "msg-rot-2", "msg-rot-3", "msg-rot-4"} {
		if _, err := store.CreateOutboxMessageWithID(id, map[string]string{"id": id}, nil); err != nil {
			t.Fatalf("CreateOutboxMessageWithID(%s): %v", id, err)
		}
	}

	var authMode string
	var seenOps []umaispool.Operation
	h, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:     store,
		RoutePrefix: "/",
		Authorizer: func(r *http.Request, op umaispool.Operation) (umaispool.Principal, error) {
			seenOps = append(seenOps, op)
			switch authMode {
			case "unauth":
				return umaispool.Principal{}, umaispool.ErrUnauthorized
			case "forbidden":
				return umaispool.Principal{}, umaispool.ErrForbidden
			case "boom":
				return umaispool.Principal{}, errors.New("backend auth service unavailable")
			default:
				return umaispool.Principal{
					Subject:    "alice",
					SessionKey: r.Header.Get("X-Test-Session"),
				}, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	endpoints := []struct {
		method string
		path   string
		body   string
		ct     string
		wantOp umaispool.Operation
	}{
		{"GET", "/outbox", "", "", umaispool.OpOutboxList},
		{"GET", "/outbox/msg-rot-1", "", "", umaispool.OpOutboxRead},
		{"GET", "/outbox/msg-rot-1/attachments/a.txt", "", "", umaispool.OpOutboxRead},
		{"POST", "/outbox/ack", `{"ids":["msg-rot-1"]}`, "application/json", umaispool.OpOutboxAck},
		{"POST", "/inbox/acceptance", `{"ids":["msg-rot-1"]}`, "application/json", umaispool.OpAcceptanceLookup},
		{"POST", "/inbox", "--b\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\nm1\r\n--b--\r\n", "multipart/form-data; boundary=b", umaispool.OpInboxAccept},
		{"GET", "/inbox", "", "", umaispool.OpInboxRead},
		{"GET", "/inbox/m1", "", "", umaispool.OpInboxRead},
		{"GET", "/inbox/m1/attachments/a.txt", "", "", umaispool.OpInboxRead},
		{"GET", "/accepted", "", "", umaispool.OpInboxRead},
		{"GET", "/accepted/receipts", "", "", umaispool.OpInboxRead},
	}

	for _, mode := range []struct {
		name       string
		wantStatus int
	}{
		{"unauth", http.StatusUnauthorized},
		{"forbidden", http.StatusForbidden},
		{"boom", http.StatusUnauthorized}, // Unexpected error must fail closed with 401
	} {
		authMode = mode.name
		for _, ep := range endpoints {
			seenOps = nil
			req, _ := http.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
			if ep.ct != "" {
				req.Header.Set("Content-Type", ep.ct)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != mode.wantStatus {
				t.Fatalf("Mode %s on %s %s: expected status %d, got %d", mode.name, ep.method, ep.path, mode.wantStatus, rec.Code)
			}
			if len(seenOps) != 1 || seenOps[0] != ep.wantOp {
				t.Fatalf("Mode %s on %s %s: expected operation %q, got %v", mode.name, ep.method, ep.path, ep.wantOp, seenOps)
			}
		}
	}

	// Verify Principal.SessionKey deterministically rotates unclaimed outbox ordering across distinct sessions
	authMode = "allow"
	firstIDs := make(map[string]bool)
	for _, sk := range []string{"sess-a", "sess-b", "sess-c", "sess-d", "sess-e", "sess-f"} {
		req, _ := http.NewRequest("GET", "/outbox", nil)
		req.Header.Set("X-Test-Session", sk)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK on /outbox, got %d", rec.Code)
		}
		var msgs []umaispool.Message
		if err := json.Unmarshal(rec.Body.Bytes(), &msgs); err != nil || len(msgs) != 4 {
			t.Fatalf("Expected 4 outbox messages, got %d (err=%v)", len(msgs), err)
		}
		firstIDs[msgs[0].ID] = true
	}
	if len(firstIDs) < 2 {
		t.Errorf("Expected SessionKey rotation to distribute initial outbox position across sessions, got %v", firstIDs)
	}
}

func TestSpoolHandler_CustomIdentities_RoutePrefix_CSRF_And_OctetStreamDownloads(t *testing.T) {
	pubCRM, privCRM, _ := ed25519.GenerateKey(rand.Reader)
	pubERP, privERP, _ := ed25519.GenerateKey(rand.Reader)

	crmHexPriv := hex.EncodeToString(privCRM.Seed())
	erpHexPub := hex.EncodeToString(pubERP)
	_, parsedCRMPriv, parsedERPPub, err := umaispool.ParseSigningKeys(crmHexPriv, erpHexPub)
	if err != nil {
		t.Fatalf("ParseSigningKeys: %v", err)
	}

	storeCRM, _ := umaispool.NewStorage(t.TempDir(), 10*1024*1024)
	if err := storeCRM.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "https://crm.example.com",
		PeerIdentity:  "https://erp.example.com",
		PrivateKey:    parsedCRMPriv,
		PeerPublicKey: parsedERPPub,
	}); err != nil {
		t.Fatalf("SetSigningConfig CRM: %v", err)
	}

	storeERP, _ := umaispool.NewStorage(t.TempDir(), 10*1024*1024)
	if err := storeERP.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "https://erp.example.com",
		PeerIdentity:  "https://crm.example.com",
		PrivateKey:    privERP,
		PeerPublicKey: pubCRM,
	}); err != nil {
		t.Fatalf("SetSigningConfig ERP: %v", err)
	}

	allowAll := func(_ *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
		return umaispool.Principal{Subject: "integrator"}, nil
	}
	handlerCRM, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:              storeCRM,
		Authorizer:           allowAll,
		RoutePrefix:          "/umai-spool",
		AllowedServerOrigins: []string{"https://crm.example.com"},
	})
	if err != nil {
		t.Fatalf("NewHandler CRM: %v", err)
	}
	handlerERP, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:              storeERP,
		Authorizer:           allowAll,
		RoutePrefix:          "/umai-spool",
		AllowedServerOrigins: []string{"https://erp.example.com"},
	})
	if err != nil {
		t.Fatalf("NewHandler ERP: %v", err)
	}

	// 1. Publish signed message on CRM with an HTML file attachment
	htmlPayload := []byte("<!doctype html><script>alert('xss')</script>")
	outMsg, err := storeCRM.CreateOutboxMessageWithID(
		"order-2026-0001",
		map[string]any{"order_id": "2026-0001", "total": 4200},
		[]umaispool.AttachmentReader{{Name: "preview.html", Reader: bytes.NewReader(htmlPayload)}},
	)
	if err != nil {
		t.Fatalf("CreateOutboxMessageWithID: %v", err)
	}

	// 2. Download attachment via standalone spool handler: MUST return application/octet-stream and sandbox CSP
	dlReq, _ := http.NewRequest("GET", "/umai-spool/outbox/order-2026-0001/attachments/preview.html", nil)
	dlRec := httptest.NewRecorder()
	handlerCRM.ServeHTTP(dlRec, dlReq)
	if dlRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK downloading outbox attachment, got %d", dlRec.Code)
	}
	if ct := dlRec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Expected Content-Type application/octet-stream for .html attachment download, got %q", ct)
	}
	if csp := dlRec.Header().Get("Content-Security-Policy"); csp != "default-src 'none'; sandbox" {
		t.Errorf("Expected sandbox CSP on attachment download, got %q", csp)
	}
	dlBytes, _ := io.ReadAll(dlRec.Body)
	if !bytes.Equal(dlBytes, htmlPayload) {
		t.Fatalf("Downloaded bytes mismatch")
	}

	// 3. Standalone CSRF checks on ERP handler
	crossOriginReq, _ := http.NewRequest("POST", "/umai-spool/inbox/acceptance", strings.NewReader(`{"ids":["order-2026-0001"]}`))
	crossOriginReq.Header.Set("Content-Type", "application/json")
	crossOriginReq.Header.Set("Origin", "https://attacker.example")
	crossRec := httptest.NewRecorder()
	handlerERP.ServeHTTP(crossRec, crossOriginReq)
	if crossRec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for cross-origin POST on standalone spool handler, got %d", crossRec.Code)
	}

	cookieNoCSRFReq, _ := http.NewRequest("POST", "/umai-spool/inbox/acceptance", strings.NewReader(`{"ids":["order-2026-0001"]}`))
	cookieNoCSRFReq.Header.Set("Content-Type", "application/json")
	cookieNoCSRFReq.AddCookie(&http.Cookie{Name: "erp_sess", Value: "123"})
	cookieNoCSRFRec := httptest.NewRecorder()
	handlerERP.ServeHTTP(cookieNoCSRFRec, cookieNoCSRFReq)
	if cookieNoCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for cookie-bearing POST without Origin or X-UMAI-CSRF, got %d", cookieNoCSRFRec.Code)
	}

	// 4. Reject malformed JSON in multipart payload on POST /inbox (never silently coerce to raw string)
	var badPayloadBuf bytes.Buffer
	badMW := multipart.NewWriter(&badPayloadBuf)
	_ = badMW.WriteField("id", outMsg.ID)
	_ = badMW.WriteField("payload", "{not-json")
	_ = badMW.WriteField("signature", outMsg.Signature)
	_ = badMW.Close()
	badReq, _ := http.NewRequest("POST", "/umai-spool/inbox", &badPayloadBuf)
	badReq.Header.Set("Content-Type", badMW.FormDataContentType())
	badReq.Header.Set("Origin", "https://erp.example.com")
	badRec := httptest.NewRecorder()
	handlerERP.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for malformed multipart payload JSON, got %d", badRec.Code)
	}

	// 5. Deliver valid signed message to ERP (using AllowedServerOrigins match) and acknowledge on CRM
	var goodBuf bytes.Buffer
	goodMW := multipart.NewWriter(&goodBuf)
	_ = goodMW.WriteField("id", outMsg.ID)
	pBytes, _ := json.Marshal(outMsg.Payload)
	_ = goodMW.WriteField("payload", string(pBytes))
	_ = goodMW.WriteField("signature", outMsg.Signature)
	_ = goodMW.WriteField("attachment_meta", `[{"name":"preview.html"}]`)
	part, _ := goodMW.CreateFormFile("attachments", "preview.html")
	_, _ = part.Write(dlBytes)
	_ = goodMW.Close()

	acceptReq, _ := http.NewRequest("POST", "/umai-spool/inbox", &goodBuf)
	acceptReq.Header.Set("Content-Type", goodMW.FormDataContentType())
	acceptReq.Header.Set("Origin", "https://erp.example.com")
	acceptRec := httptest.NewRecorder()
	handlerERP.ServeHTTP(acceptRec, acceptReq)
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK accepting signed message on ERP, got %d (%s)", acceptRec.Code, acceptRec.Body.String())
	}

	var acceptBody struct {
		Accepted   bool   `json:"accepted"`
		AckReceipt string `json:"ack_receipt"`
	}
	_ = json.Unmarshal(acceptRec.Body.Bytes(), &acceptBody)
	if !acceptBody.Accepted || acceptBody.AckReceipt == "" {
		t.Fatalf("Expected accepted=true with signed AckReceipt, got %+v", acceptBody)
	}

	ackBody, _ := json.Marshal(map[string]any{
		"ids":      []string{outMsg.ID},
		"receipts": map[string]string{outMsg.ID: acceptBody.AckReceipt},
	})
	ackReq, _ := http.NewRequest("POST", "/umai-spool/outbox/ack", bytes.NewReader(ackBody))
	ackReq.Header.Set("Content-Type", "application/json")
	ackReq.Header.Set("Origin", "https://crm.example.com")
	ackRec := httptest.NewRecorder()
	handlerCRM.ServeHTTP(ackRec, ackReq)
	if ackRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK acknowledging receipt on CRM, got %d (%s)", ackRec.Code, ackRec.Body.String())
	}
	remaining, _ := storeCRM.ListOutbox()
	if len(remaining) != 0 {
		t.Fatalf("Expected CRM outbox to be empty after verified ACK, got %d", len(remaining))
	}
}
