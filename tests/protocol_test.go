package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
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
	req.Header.Set("X-UMAI-Session", sessionID)
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
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	msgID := "msg-dup-001"
	payload := `{"text":"First send"}`

	// 1. Send first PUT
	var buf1 bytes.Buffer
	mw1 := multipart.NewWriter(&buf1)
	_ = mw1.WriteField("id", msgID)
	_ = mw1.WriteField("payload", payload)
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

	// 2. Attempt to forge an ACK receipt on A without B having accepted it
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
