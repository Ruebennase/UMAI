package tests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/umai-protocol/umai/pkg/umaiserver"
)

// TestApp wraps a server instance and handles in-memory HTTP requests.
type TestApp struct {
	Server    *umaiserver.Server
	SessionID string
	Role      string
}

// setupApp creates an in-memory application instance with active session.
func setupApp(t *testing.T, role string, peerOrigin string) *TestApp {
	dataDir := t.TempDir()
	cfg := umaiserver.DefaultConfig(role)
	cfg.DataDir = dataDir
	cfg.PeerOrigin = peerOrigin

	staticDir := t.TempDir()
	_ = os.WriteFile(staticDir+"/index.html", []byte("<html></html>"), 0644)

	server, err := umaiserver.NewServer(cfg, staticDir)
	if err != nil {
		t.Fatalf("NewServer error: %v", err)
	}

	sessionID, ok := server.Auth().Authenticate(cfg.AuthUsername, cfg.AuthPassword)
	if !ok {
		t.Fatalf("Failed to authenticate test session")
	}

	return &TestApp{
		Server:    server,
		SessionID: sessionID,
		Role:      role,
	}
}

// Do executes an HTTP request in-memory via the server's handler pipeline.
func (app *TestApp) Do(req *http.Request) *http.Response {
	rec := httptest.NewRecorder()
	app.Server.Handler().ServeHTTP(rec, req)
	return rec.Result()
}

func authenticatedRequest(method, url string, sessionID string, body io.Reader, contentType string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-UMAI-CSRF", "1")
	req.AddCookie(&http.Cookie{
		Name:  umaiserver.SessionCookieName,
		Value: sessionID,
	})
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}

func TestProtocol_BasicExchange_WithIntegrity(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	// 1. Create two test documents in App A
	file1Content := []byte("First attachment: binary executable data \x00\x01\x02\x03\xFF")
	file2Content := []byte("Second attachment: utf-8 text file with special characters: üöä €")

	_, err := appA.Server.Storage().SaveDocument("binary.bin", bytes.NewReader(file1Content))
	if err != nil {
		t.Fatalf("Save binary.bin: %v", err)
	}
	_, err = appA.Server.Storage().SaveDocument("report.txt", bytes.NewReader(file2Content))
	if err != nil {
		t.Fatalf("Save report.txt: %v", err)
	}

	// 2. Create Outbox message in App A with both attachments
	payload := map[string]any{
		"subject":  "Confidential Package",
		"priority": 1,
	}
	msgA, err := appA.Server.Storage().CreateOutboxMessage(payload, []string{"binary.bin", "report.txt"})
	if err != nil {
		t.Fatalf("Create outbox message: %v", err)
	}

	// Compute expected hashes
	h1 := sha256.Sum256(file1Content)
	expectedHash1 := hex.EncodeToString(h1[:])
	h2 := sha256.Sum256(file2Content)
	expectedHash2 := hex.EncodeToString(h2[:])

	// 3. App A OFFERs message ID to App B
	if appB.Server.Storage().IsAccepted(msgA.ID) {
		t.Fatalf("Message should not be accepted yet on B")
	}

	// 4. App B sends GET for msgA.ID -> App A delivers PUT
	attPath1, _ := appA.Server.Storage().GetOutboxAttachmentPath(msgA.ID, "binary.bin")
	attPath2, _ := appA.Server.Storage().GetOutboxAttachmentPath(msgA.ID, "report.txt")
	f1Data, _ := os.ReadFile(attPath1)
	f2Data, _ := os.ReadFile(attPath2)

	// Prepare multipart form for B's /api/inbox (including A's Ed25519 signature)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("id", msgA.ID)
	payloadJSON, _ := json.Marshal(msgA.Payload)
	_ = mw.WriteField("payload", string(payloadJSON))
	_ = mw.WriteField("signature", msgA.Signature)

	part1, _ := mw.CreateFormFile("attachments", "binary.bin")
	_, _ = part1.Write(f1Data)
	part2, _ := mw.CreateFormFile("attachments", "report.txt")
	_, _ = part2.Write(f2Data)
	_ = mw.Close()

	req, err := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &buf, mw.FormDataContentType())
	if err != nil {
		t.Fatalf("Create request to B: %v", err)
	}
	res := appB.Do(req)
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from B, got %d", res.StatusCode)
	}

	var acceptResp struct {
		Accepted   bool   `json:"accepted"`
		AckReceipt string `json:"ack_receipt"`
	}
	_ = json.NewDecoder(res.Body).Decode(&acceptResp)
	if acceptResp.AckReceipt == "" {
		t.Fatalf("Expected B to return a cryptographic ack_receipt")
	}

	// 5. App B must now report message as accepted (Rule 4)
	if !appB.Server.Storage().IsAccepted(msgA.ID) {
		t.Fatalf("App B failed to record accepted message ID")
	}

	// Verify attachments integrity on App B
	inboxMsg, err := appB.Server.Storage().GetInboxMessage(msgA.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve inbox message from B: %v", err)
	}
	if len(inboxMsg.Attachments) != 2 {
		t.Fatalf("Expected 2 attachments on B, got %d", len(inboxMsg.Attachments))
	}

	savedAtt1Path, err := appB.Server.Storage().GetInboxAttachmentPath(msgA.ID, "binary.bin")
	if err != nil {
		t.Fatalf("Get attachment 1 on B: %v", err)
	}
	savedData1, _ := os.ReadFile(savedAtt1Path)
	if !bytes.Equal(savedData1, file1Content) {
		t.Errorf("Attachment 1 data on B does not match original bytes!")
	}
	if hex.EncodeToString(sha256New(savedData1)) != expectedHash1 {
		t.Errorf("Attachment 1 SHA-256 on B differs from original!")
	}

	savedAtt2Path, err := appB.Server.Storage().GetInboxAttachmentPath(msgA.ID, "report.txt")
	if err != nil {
		t.Fatalf("Get attachment 2 on B: %v", err)
	}
	savedData2, _ := os.ReadFile(savedAtt2Path)
	if !bytes.Equal(savedData2, file2Content) {
		t.Errorf("Attachment 2 data on B does not match original bytes!")
	}
	if hex.EncodeToString(sha256New(savedData2)) != expectedHash2 {
		t.Errorf("Attachment 2 SHA-256 on B differs from original!")
	}

	// 6. App B sends signed ACK -> App A verifies receipt and cleans its outbox (Rule 6)
	if err := appA.Server.Storage().AcknowledgeMessagesVerified([]string{msgA.ID}, map[string]string{msgA.ID: acceptResp.AckReceipt}); err != nil {
		t.Fatalf("App A failed to verify and acknowledge receipt: %v", err)
	}

	outboxA, _ := appA.Server.Storage().ListOutbox()
	if len(outboxA) != 0 {
		t.Errorf("Expected App A outbox to be cleaned, still has %d messages", len(outboxA))
	}
}

func TestProtocol_ZeroAttachmentsExchange(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	msg, err := appA.Server.Storage().CreateOutboxMessage(map[string]string{"type": "ping"}, []string{})
	if err != nil {
		t.Fatalf("Create outbox message: %v", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("id", msg.ID)
	_ = mw.WriteField("payload", `{"type":"ping"}`)
	_ = mw.WriteField("signature", msg.Signature)
	_ = mw.Close()

	req, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &buf, mw.FormDataContentType())
	res := appB.Do(req)
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Failed to accept zero-attachment message on B: status %d", res.StatusCode)
	}

	if !appB.Server.Storage().IsAccepted(msg.ID) {
		t.Errorf("Zero-attachment message was not recorded as accepted")
	}
}

func TestProtocol_DuplicatePrevention(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	_, _ = appA.Server.Storage().SaveDocument("file.txt", bytes.NewReader([]byte("content")))
	msgA, err := appA.Server.Storage().CreateOutboxMessage(map[string]string{"text": "First send"}, []string{"file.txt"})
	if err != nil {
		t.Fatalf("CreateOutboxMessage: %v", err)
	}
	msgID := msgA.ID
	pBytes, _ := json.Marshal(msgA.Payload)
	payload := string(pBytes)

	// 1. Send first PUT
	var buf1 bytes.Buffer
	mw1 := multipart.NewWriter(&buf1)
	_ = mw1.WriteField("id", msgID)
	_ = mw1.WriteField("payload", payload)
	_ = mw1.WriteField("signature", msgA.Signature)
	p1, _ := mw1.CreateFormFile("attachments", "file.txt")
	_, _ = p1.Write([]byte("content"))
	_ = mw1.Close()

	req1, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &buf1, mw1.FormDataContentType())
	res1 := appB.Do(req1)
	defer res1.Body.Close()

	if res1.StatusCode != http.StatusOK {
		t.Fatalf("First send failed: %d", res1.StatusCode)
	}

	inboxBefore, _ := appB.Server.Storage().ListInbox()
	if len(inboxBefore) != 1 {
		t.Fatalf("Expected 1 message in inbox, got %d", len(inboxBefore))
	}

	// 2. Deliver duplicate PUT with same message ID
	var buf2 bytes.Buffer
	mw2 := multipart.NewWriter(&buf2)
	_ = mw2.WriteField("id", msgID)
	_ = mw2.WriteField("payload", payload)
	_ = mw2.WriteField("signature", msgA.Signature)
	p2, _ := mw2.CreateFormFile("attachments", "file.txt")
	_, _ = p2.Write([]byte("content"))
	_ = mw2.Close()

	req2, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &buf2, mw2.FormDataContentType())
	res2 := appB.Do(req2)
	defer res2.Body.Close()

	if res2.StatusCode != http.StatusOK {
		t.Fatalf("Duplicate send should return 200 OK without failing, got %d", res2.StatusCode)
	}

	inboxAfter, _ := appB.Server.Storage().ListInbox()
	if len(inboxAfter) != 1 {
		t.Errorf("Duplicate prevention failed! Message was imported multiple times, count: %d", len(inboxAfter))
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestProtocol_InterruptedTransfer_AllOrNothing(t *testing.T) {
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	msgID := "msg-interrupt-999"

	// Simulate an interrupted network transfer mid-file
	_, err := appB.Server.Storage().AcceptMessage(msgID, "payload", []umaiserver.AttachmentReader{
		{Name: "interrupted.bin", Reader: &errorReader{}},
	})
	if err == nil {
		t.Fatalf("Expected error on interrupted attachment read")
	}

	// Rule 3: The message must NOT be accepted, and no partial files should remain in inbox
	if appB.Server.Storage().IsAccepted(msgID) {
		t.Errorf("Interrupted message must NOT be marked as accepted")
	}

	inboxMsg, _ := appB.Server.Storage().GetInboxMessage(msgID)
	if inboxMsg != nil {
		t.Errorf("Partial message was exposed in inbox!")
	}
}

func sha256New(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func TestSecurity_SignedMessages_TamperAndForgeryRejection(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	_, _ = appA.Server.Storage().SaveDocument("invoice.pdf", bytes.NewReader([]byte("Original Amount: CHF 100")))
	msgA, err := appA.Server.Storage().CreateOutboxMessage(map[string]any{"amount": 100}, []string{"invoice.pdf"})
	if err != nil {
		t.Fatalf("CreateOutboxMessage: %v", err)
	}
	if msgA.Signature == "" {
		t.Fatalf("Expected CreateOutboxMessage to produce an Ed25519 signature")
	}

	// 1. Attempt to tamper with the attachment bytes in transit while keeping A's signature
	var bufTamper bytes.Buffer
	mw := multipart.NewWriter(&bufTamper)
	_ = mw.WriteField("id", msgA.ID)
	pJSON, _ := json.Marshal(msgA.Payload)
	_ = mw.WriteField("payload", string(pJSON))
	_ = mw.WriteField("signature", msgA.Signature)
	part, _ := mw.CreateFormFile("attachments", "invoice.pdf")
	_, _ = part.Write([]byte("Tampered Amount: CHF 999999"))
	_ = mw.Close()

	reqTamper, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &bufTamper, mw.FormDataContentType())
	resTamper := appB.Do(reqTamper)
	defer resTamper.Body.Close()

	if resTamper.StatusCode == http.StatusOK {
		t.Fatalf("Expected B to reject tampered attachment with invalid signature, but got 200 OK")
	}
	if appB.Server.Storage().IsAccepted(msgA.ID) {
		t.Fatalf("Tampered message must not be marked accepted on B")
	}

	// 2. Attempt signature-strip downgrade (omitting signature field entirely)
	var bufStrip bytes.Buffer
	mwStrip := multipart.NewWriter(&bufStrip)
	_ = mwStrip.WriteField("id", msgA.ID)
	_ = mwStrip.WriteField("payload", string(pJSON))
	partStrip, _ := mwStrip.CreateFormFile("attachments", "invoice.pdf")
	_, _ = partStrip.Write([]byte("Original Amount: CHF 100"))
	_ = mwStrip.Close()

	reqStrip, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &bufStrip, mwStrip.FormDataContentType())
	resStrip := appB.Do(reqStrip)
	defer resStrip.Body.Close()
	if resStrip.StatusCode == http.StatusOK {
		t.Fatalf("Expected B to reject unsigned message (signature-strip downgrade), but got 200 OK")
	}

	// 3. Attempt to forge an ACK receipt on A without B having accepted it, or with an empty receipts map
	err = appA.Server.Storage().AcknowledgeMessagesVerified([]string{msgA.ID}, map[string]string{})
	if err == nil {
		t.Fatalf("Expected A to reject empty receipts map downgrade")
	}
	err = appA.Server.Storage().AcknowledgeMessagesVerified([]string{msgA.ID}, map[string]string{
		msgA.ID: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatalf("Expected A to reject forged ACK receipt")
	}
	outboxAfterForgedAck, _ := appA.Server.Storage().ListOutbox()
	if len(outboxAfterForgedAck) != 1 {
		t.Fatalf("Outbox message on A must not be deleted on forged ACK receipt")
	}

	// 4. Verify receiver role binding in UMAI-PUT-V1: a message signed by app-a for "app-c" must be rejected by app-b
	_, privA := umaiserver.DeriveDemoKeyPair("app-a")
	sigForAppC, err := umaiserver.SignPutMessage(privA, "app-a", "app-c", msgA.ID, msgA.Payload, msgA.Attachments)
	if err != nil {
		t.Fatalf("SignPutMessage for app-c: %v", err)
	}
	var bufWrongReceiver bytes.Buffer
	mwWrong := multipart.NewWriter(&bufWrongReceiver)
	_ = mwWrong.WriteField("id", msgA.ID)
	_ = mwWrong.WriteField("payload", string(pJSON))
	_ = mwWrong.WriteField("signature", sigForAppC)
	partWrong, _ := mwWrong.CreateFormFile("attachments", "invoice.pdf")
	_, _ = partWrong.Write([]byte("Original Amount: CHF 100"))
	_ = mwWrong.Close()

	reqWrong, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &bufWrongReceiver, mwWrong.FormDataContentType())
	resWrong := appB.Do(reqWrong)
	defer resWrong.Body.Close()
	if resWrong.StatusCode == http.StatusOK {
		t.Fatalf("Expected B to reject message signed for different receiver role (app-c), got 200 OK")
	}

	// 5. Verify non-loopback address refuses deterministic demo keys unless AllowDemoDefaults (-demo) is enabled
	nonLoopbackCfg := umaiserver.DefaultConfig("app-a")
	nonLoopbackCfg.ListenAddr = "0.0.0.0:8081"
	nonLoopbackCfg.DataDir = t.TempDir()
	if _, err := umaiserver.NewServer(nonLoopbackCfg, t.TempDir()); err == nil {
		t.Fatalf("Expected NewServer on non-loopback 0.0.0.0:8081 without explicit keys or -demo to fail")
	}
}

func TestSecurity_CSRF_StatusLeak_And_DuplicateAttachment(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")
	_, _ = appA.Server.Storage().CreateOutboxMessage(map[string]string{"s": "secret"}, nil)

	// 1. Unauthenticated /api/status must not leak outbox_ids or accepted_ids
	reqStatus, _ := http.NewRequest("GET", "/api/status", nil)
	resStatus := appA.Do(reqStatus)
	defer resStatus.Body.Close()
	var statusData map[string]any
	_ = json.NewDecoder(resStatus.Body).Decode(&statusData)
	if _, leaked := statusData["outbox_ids"]; leaked {
		t.Errorf("Unauthenticated /api/status leaked outbox_ids!")
	}
	if _, leaked := statusData["accepted_ids"]; leaked {
		t.Errorf("Unauthenticated /api/status leaked accepted_ids!")
	}

	// 2. Cross-origin POST with foreign Origin header must be blocked (CSRF protection)
	reqCSRF, _ := authenticatedRequest("POST", "/api/outbox/ack", appA.SessionID, bytes.NewReader([]byte(`{"ids":["msg-1"]}`)), "application/json")
	reqCSRF.Header.Set("Origin", "https://evil.example.org")
	resCSRF := appA.Do(reqCSRF)
	defer resCSRF.Body.Close()
	if resCSRF.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for cross-origin POST, got %d", resCSRF.StatusCode)
	}

	// 3. POST /api/outbox/ack with text/plain Content-Type must be rejected (415 Unsupported Media Type)
	reqPlain, _ := authenticatedRequest("POST", "/api/outbox/ack", appA.SessionID, bytes.NewReader([]byte(`{"ids":["msg-1"]}`)), "text/plain")
	resPlain := appA.Do(reqPlain)
	defer resPlain.Body.Close()
	if resPlain.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("Expected 415 Unsupported Media Type for text/plain JSON POST, got %d", resPlain.StatusCode)
	}

	// 4. Duplicate attachment filename in a single message must be rejected
	_, _ = appA.Server.Storage().SaveDocument("dup.txt", bytes.NewReader([]byte("hello")))
	_, err := appA.Server.Storage().CreateOutboxMessage(map[string]string{}, []string{"dup.txt", "dup.txt"})
	if err == nil {
		t.Errorf("Expected error when creating message with duplicate attachment filenames")
	}
}

func TestConcurrentSessions_SoftLeaseAndNextBestSelection(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")

	m1, _ := appA.Server.Storage().CreateOutboxMessage(map[string]string{"seq": "1"}, nil)
	m2, _ := appA.Server.Storage().CreateOutboxMessage(map[string]string{"seq": "2"}, nil)
	m3, _ := appA.Server.Storage().CreateOutboxMessage(map[string]string{"seq": "3"}, nil)

	initialList, err := appA.Server.Storage().ListOutbox()
	if err != nil || len(initialList) != 3 {
		t.Fatalf("Expected 3 outbox messages, got %d (err=%v)", len(initialList), err)
	}
	firstID := initialList[0].ID

	// Browser 1 begins transferring firstID by calling GetOutboxMessage(firstID),
	// which places a 15-second soft in-flight lease on firstID.
	_, err = appA.Server.Storage().GetOutboxMessage(firstID)
	if err != nil {
		t.Fatalf("GetOutboxMessage(%s) failed: %v", firstID, err)
	}

	// Browser 2 now queries ListOutbox() and should automatically pick the next unclaimed message first,
	// with the in-flight firstID deprioritized to the end of the slice.
	nextList, err := appA.Server.Storage().ListOutbox()
	if err != nil || len(nextList) != 3 {
		t.Fatalf("Expected 3 outbox messages on second query, got %d", len(nextList))
	}
	if nextList[0].ID == firstID {
		t.Errorf("Expected in-flight message %s to be deprioritized, but it is still first in queue", firstID)
	}
	if nextList[len(nextList)-1].ID != firstID {
		t.Errorf("Expected in-flight message %s at the end of the queue, got %s", firstID, nextList[len(nextList)-1].ID)
	}
	_ = m1
	_ = m2
	_ = m3
}

func TestSecurity_StrictCSP_CookieCSRF_NilPayload_And_DuplicateProbe(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	// 1. Verify strict CSP: no 'unsafe-inline' in script-src and no localhost:* wildcard in connect-src
	reqStatus, _ := http.NewRequest("GET", "/api/status", nil)
	resStatus := appA.Do(reqStatus)
	defer resStatus.Body.Close()
	csp := resStatus.Header.Get("Content-Security-Policy")
	if bytes.Contains([]byte(csp), []byte("script-src 'self' 'unsafe-inline'")) {
		t.Errorf("CSP must not allow 'unsafe-inline' in script-src: %s", csp)
	}
	if bytes.Contains([]byte(csp), []byte("connect-src 'self' localhost:*")) {
		t.Errorf("CSP must not allow localhost:* wildcard in connect-src: %s", csp)
	}

	// 2. Verify cookie-authenticated POST without Origin or X-UMAI-CSRF is blocked (stripped-Origin form CSRF defense)
	reqCookieCSRF, _ := http.NewRequest("POST", "/api/docs", bytes.NewReader([]byte("dummy")))
	reqCookieCSRF.AddCookie(&http.Cookie{Name: "umai_session_a", Value: appA.SessionID})
	resCookieCSRF := appA.Do(reqCookieCSRF)
	defer resCookieCSRF.Body.Close()
	if resCookieCSRF.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden on cookie-only POST without Origin/CSRF header, got %d", resCookieCSRF.StatusCode)
	}

	// 3. Verify nil payload signing matches '{}' JSON payload in transit, and verify attachment download sandbox CSP
	_, _ = appA.Server.Storage().SaveDocument("note.html", bytes.NewReader([]byte("<script>alert(1)</script>")))
	reqDl, _ := authenticatedRequest("GET", "/api/docs/note.html", appA.SessionID, nil, "")
	resDl := appA.Do(reqDl)
	defer resDl.Body.Close()
	if dlCSP := resDl.Header.Get("Content-Security-Policy"); dlCSP != "default-src 'none'; sandbox" {
		t.Errorf("Expected attachment download sandbox CSP, got %q", dlCSP)
	}

	msgNil, err := appA.Server.Storage().CreateOutboxMessage(nil, nil)
	if err != nil {
		t.Fatalf("CreateOutboxMessage(nil): %v", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("id", msgNil.ID)
	_ = mw.WriteField("payload", "{}")
	_ = mw.WriteField("signature", msgNil.Signature)
	_ = mw.Close()

	reqAccept, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &buf, mw.FormDataContentType())
	resAccept := appB.Do(reqAccept)
	defer resAccept.Body.Close()
	if resAccept.StatusCode != http.StatusOK {
		t.Fatalf("Expected nil-payload message to verify cleanly with '{}', got %d", resAccept.StatusCode)
	}

	// 4. Verify duplicate POST /api/inbox probe with missing/forged signature for an already-accepted ID is rejected
	var bufProbe bytes.Buffer
	mwProbe := multipart.NewWriter(&bufProbe)
	_ = mwProbe.WriteField("id", msgNil.ID)
	_ = mwProbe.WriteField("payload", "{}")
	_ = mwProbe.WriteField("signature", "deadbeef")
	_ = mwProbe.Close()

	reqProbe, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &bufProbe, mwProbe.FormDataContentType())
	resProbe := appB.Do(reqProbe)
	defer resProbe.Body.Close()
	if resProbe.StatusCode == http.StatusOK {
		t.Errorf("Expected duplicate POST /api/inbox with invalid signature to be rejected, got 200 OK")
	}

	// 5. Verify static directory and DataDir overlap is rejected at startup (F1)
	overlapCfg := umaiserver.DefaultConfig("app-a")
	overlapCfg.DataDir = filepath.Join(appA.Server.Config().DataDir, "sub")
	if _, err := umaiserver.NewServer(overlapCfg, appA.Server.Config().DataDir); err == nil {
		t.Errorf("Expected NewServer to reject overlapping staticDir and DataDir")
	}

	// 6. Verify scheme-aware Origin check rejects http:// Origin on an https request (F7)
	reqMismatchScheme, _ := authenticatedRequest("POST", "/api/outbox/ack", appA.SessionID, bytes.NewReader([]byte(`{"ids":[]}`)), "application/json")
	reqMismatchScheme.RemoteAddr = "127.0.0.1:54321"
	reqMismatchScheme.Header.Set("X-Forwarded-Proto", "https")
	reqMismatchScheme.Header.Set("Origin", "http://127.0.0.1:8081")
	resMismatch := appA.Do(reqMismatchScheme)
	defer resMismatch.Body.Close()
	if resMismatch.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for scheme-mismatched Origin header, got %d", resMismatch.StatusCode)
	}

	// 7. Verify exact 64-bit integer precision in CanonicalPutDigest (F5): 9007199254740992 vs 9007199254740993
	d1, err1 := umaiserver.CanonicalPutDigest("app-a", "app-b", "msg-int", json.RawMessage(`{"n":9007199254740992}`), nil)
	d2, err2 := umaiserver.CanonicalPutDigest("app-a", "app-b", "msg-int", json.RawMessage(`{"n":9007199254740993}`), nil)
	if err1 != nil || err2 != nil || d1 == d2 {
		t.Errorf("Expected distinct canonical digests for 9007199254740992 and 9007199254740993, got equal (%x)", d1)
	}

	// 8. Verify scalar false payload round-trips with valid signature verification (F6)
	msgFalse, err := appA.Server.Storage().CreateOutboxMessage(false, nil)
	if err != nil {
		t.Fatalf("CreateOutboxMessage(false): %v", err)
	}
	var bufFalse bytes.Buffer
	mwFalse := multipart.NewWriter(&bufFalse)
	_ = mwFalse.WriteField("id", msgFalse.ID)
	_ = mwFalse.WriteField("payload", "false")
	_ = mwFalse.WriteField("signature", msgFalse.Signature)
	_ = mwFalse.Close()
	reqFalse, _ := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &bufFalse, mwFalse.FormDataContentType())
	resFalse := appB.Do(reqFalse)
	defer resFalse.Body.Close()
	if resFalse.StatusCode != http.StatusOK {
		t.Errorf("Expected scalar false payload message to verify cleanly, got %d", resFalse.StatusCode)
	}
}

func encodeUncompressedP256PublicKey(pub *ecdsa.PublicKey) string {
	raw := make([]byte, 65)
	raw[0] = 0x04
	pub.X.FillBytes(raw[1:33])
	pub.Y.FillBytes(raw[33:65])
	return hex.EncodeToString(raw)
}

func signP1363(t *testing.T, priv *ecdsa.PrivateKey, msg string) string {
	digest := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return hex.EncodeToString(sig)
}

func TestAuth_EphemeralPoPBootstrap_And_TamperRejection(t *testing.T) {
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")

	// 1. Generate ephemeral P-256 key pair (simulating non-extractable WebCrypto key inside embedded iframe)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := encodeUncompressedP256PublicKey(&privKey.PublicKey)

	// 2. Call POST /api/auth/bootstrap/init
	initBody, _ := json.Marshal(map[string]string{"public_key": pubHex})
	reqInit, _ := http.NewRequest("POST", "/api/auth/bootstrap/init", bytes.NewReader(initBody))
	reqInit.Header.Set("Content-Type", "application/json")
	reqInit.Header.Set("X-UMAI-CSRF", "1")
	resInit := appA.Do(reqInit)
	defer resInit.Body.Close()
	if resInit.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from bootstrap/init, got %d", resInit.StatusCode)
	}
	var initResp struct {
		TxID        string `json:"tx_id"`
		OpenerNonce string `json:"opener_nonce"`
		Challenge   string `json:"challenge"`
	}
	_ = json.NewDecoder(resInit.Body).Decode(&initResp)
	if initResp.TxID == "" || initResp.OpenerNonce == "" || initResp.Challenge == "" {
		t.Fatalf("Incomplete bootstrap init response: %+v", initResp)
	}

	// 3. Before top-level authorization, redeem returns 202 Accepted (pending) without consuming transaction
	validSig := signP1363(t, privKey, fmt.Sprintf("UMAI-BOOTSTRAP-V1:%s:%s", initResp.TxID, initResp.Challenge))
	redeemBody, _ := json.Marshal(map[string]string{"tx_id": initResp.TxID, "signature": validSig})
	reqPending, _ := http.NewRequest("POST", "/api/auth/bootstrap/redeem", bytes.NewReader(redeemBody))
	reqPending.Header.Set("Content-Type", "application/json")
	reqPending.Header.Set("X-UMAI-CSRF", "1")
	resPending := appA.Do(reqPending)
	defer resPending.Body.Close()
	if resPending.StatusCode != http.StatusAccepted {
		t.Fatalf("Expected 202 Accepted while bootstrap is pending, got %d", resPending.StatusCode)
	}

	// 4. Authorize with wrong opener_nonce must be rejected (400 Bad Request)
	badAuthBody, _ := json.Marshal(map[string]string{"tx_id": initResp.TxID, "opener_nonce": "wrong-nonce"})
	reqBadAuth, _ := authenticatedRequest("POST", "/api/auth/bootstrap/authorize", appA.SessionID, bytes.NewReader(badAuthBody), "application/json")
	resBadAuth := appA.Do(reqBadAuth)
	defer resBadAuth.Body.Close()
	if resBadAuth.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for wrong opener_nonce, got %d", resBadAuth.StatusCode)
	}

	// 5. Authorize with valid opener_nonce and top-level authenticated session succeeds and returns auth_secret
	goodAuthBody, _ := json.Marshal(map[string]string{"tx_id": initResp.TxID, "opener_nonce": initResp.OpenerNonce})
	reqGoodAuth, _ := authenticatedRequest("POST", "/api/auth/bootstrap/authorize", appA.SessionID, bytes.NewReader(goodAuthBody), "application/json")
	resGoodAuth := appA.Do(reqGoodAuth)
	defer resGoodAuth.Body.Close()
	if resGoodAuth.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from bootstrap/authorize, got %d", resGoodAuth.StatusCode)
	}
	var authResp struct {
		Authorized bool   `json:"authorized"`
		TxID       string `json:"tx_id"`
		AuthSecret string `json:"auth_secret"`
	}
	_ = json.NewDecoder(resGoodAuth.Body).Decode(&authResp)
	if !authResp.Authorized || authResp.AuthSecret == "" {
		t.Fatalf("Expected auth_secret from bootstrap/authorize, got %+v", authResp)
	}

	// 5b. Verify D1 protection: attempting to redeem without auth_secret (e.g. remote attacker who only knows tx_id & challenge) fails
	reqInit2, _ := http.NewRequest("POST", "/api/auth/bootstrap/init", bytes.NewReader(initBody))
	reqInit2.Header.Set("Content-Type", "application/json")
	reqInit2.Header.Set("X-UMAI-CSRF", "1")
	resInit2 := appA.Do(reqInit2)
	defer resInit2.Body.Close()
	var initResp2 struct {
		TxID        string `json:"tx_id"`
		OpenerNonce string `json:"opener_nonce"`
		Challenge   string `json:"challenge"`
	}
	_ = json.NewDecoder(resInit2.Body).Decode(&initResp2)
	authBody2, _ := json.Marshal(map[string]string{"tx_id": initResp2.TxID, "opener_nonce": initResp2.OpenerNonce})
	reqAuth2, _ := authenticatedRequest("POST", "/api/auth/bootstrap/authorize", appA.SessionID, bytes.NewReader(authBody2), "application/json")
	resAuth2 := appA.Do(reqAuth2)
	_ = resAuth2.Body.Close()
	attackerSigWithoutSecret := signP1363(t, privKey, fmt.Sprintf("UMAI-BOOTSTRAP-V1:%s:%s:", initResp2.TxID, initResp2.Challenge))
	attackerRedeemBody, _ := json.Marshal(map[string]string{"tx_id": initResp2.TxID, "auth_secret": "", "signature": attackerSigWithoutSecret})
	reqAttackerRedeem, _ := http.NewRequest("POST", "/api/auth/bootstrap/redeem", bytes.NewReader(attackerRedeemBody))
	reqAttackerRedeem.Header.Set("Content-Type", "application/json")
	reqAttackerRedeem.Header.Set("X-UMAI-CSRF", "1")
	resAttackerRedeem := appA.Do(reqAttackerRedeem)
	defer resAttackerRedeem.Body.Close()
	if resAttackerRedeem.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized when redeeming without top-level auth_secret (D1), got %d", resAttackerRedeem.StatusCode)
	}

	// 6. Redeem with valid auth_secret (delivered over window.opener) + Proof-of-Possession signature succeeds and issues HttpOnly session cookie
	validSigWithSecret := signP1363(t, privKey, fmt.Sprintf("UMAI-BOOTSTRAP-V1:%s:%s:%s", initResp.TxID, initResp.Challenge, authResp.AuthSecret))
	redeemWithSecretBody, _ := json.Marshal(map[string]string{
		"tx_id":       initResp.TxID,
		"auth_secret": authResp.AuthSecret,
		"signature":   validSigWithSecret,
	})
	reqRedeem, _ := http.NewRequest("POST", "/api/auth/bootstrap/redeem", bytes.NewReader(redeemWithSecretBody))
	reqRedeem.Header.Set("Content-Type", "application/json")
	reqRedeem.Header.Set("X-UMAI-CSRF", "1")
	resRedeem := appA.Do(reqRedeem)
	defer resRedeem.Body.Close()
	if resRedeem.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK from bootstrap/redeem, got %d", resRedeem.StatusCode)
	}
	cookies := resRedeem.Cookies()
	if len(cookies) == 0 || !cookies[0].HttpOnly {
		t.Fatalf("Expected HttpOnly session cookie from bootstrap/redeem, got %+v", cookies)
	}

	// 7. Replaying the same tx_id a second time must fail (single-use redemption)
	reqReplay, _ := http.NewRequest("POST", "/api/auth/bootstrap/redeem", bytes.NewReader(redeemWithSecretBody))
	reqReplay.Header.Set("Content-Type", "application/json")
	reqReplay.Header.Set("X-UMAI-CSRF", "1")
	resReplay := appA.Do(reqReplay)
	defer resReplay.Body.Close()
	if resReplay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized on replayed bootstrap redemption, got %d", resReplay.StatusCode)
	}

	// 8. Verify D4 protection: loopback ListenAddr with non-loopback PeerOrigin refuses demo defaults
	_, err = umaiserver.NewServer(umaiserver.Config{
		AppName:      "Public Peer Behind Reverse Proxy",
		Role:         "app-a",
		ListenAddr:   "127.0.0.1:8081",
		PeerOrigin:   "https://app-b.example.net",
		DataDir:      t.TempDir(),
		AuthUsername: "admin",
		AuthPassword: "umai123",
	}, "")
	if err == nil {
		t.Fatalf("Expected NewServer to refuse demo defaults when PeerOrigin is non-loopback (D4)")
	}
}
