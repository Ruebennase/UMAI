package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/umai-protocol/umai/pkg/umaispool"
)

func TestC2_MediaTypeValidation_Signing_And_AttachmentMetaContract(t *testing.T) {
	// 1. ValidateMediaType normalization & rejection rules
	validCases := map[string]string{
		"":                        "",
		"   ":                     "",
		"application/pdf":         "application/pdf",
		"  Application/PDF ":      "application/pdf",
		"IMAGE/svg+xml":           "image/svg+xml",
		"application/vnd.api+json": "application/vnd.api+json",
	}
	for in, want := range validCases {
		got, err := umaispool.ValidateMediaType(in)
		if err != nil || got != want {
			t.Fatalf("ValidateMediaType(%q) = (%q, %v), want (%q, nil)", in, got, err, want)
		}
	}

	invalidCases := []string{
		"text/plain; charset=utf-8",
		"text/plain;charset=utf-8",
		"application/",
		"/pdf",
		"application",
		"app/sub/extra",
		"text /plain",
		"text/pla\x00in",
		"text/pläin",
		"-bad/start",
		"bad/-start",
		strings.Repeat("a", 120) + "/bbbbbbbbbb", // > 127 bytes
	}
	for _, in := range invalidCases {
		if _, err := umaispool.ValidateMediaType(in); !errors.Is(err, umaispool.ErrInvalidMediaType) {
			t.Fatalf("ValidateMediaType(%q) expected ErrInvalidMediaType, got %v", in, err)
		}
	}

	// 2. End-to-end signed round-trip: absent media_type, non-empty media_type, and tampered media_type
	pubSender, privSender, _ := ed25519.GenerateKey(rand.Reader)
	_, privReceiver, _ := ed25519.GenerateKey(rand.Reader)

	senderDir := t.TempDir()
	receiverDir := t.TempDir()

	// Publish via stateless Publish with mixed absent ("") and mixed-case ("Application/PDF") media_type
	rawBin := []byte{0x00, 0x01, 0x02, 0x03}
	pdfBytes := []byte("%PDF-1.7 sample")
	pubMsg, err := umaispool.Publish(umaispool.PublishRequest{
		DataDir: senderDir,
		ID:      "c2-roundtrip-1",
		Payload: map[string]any{"case": "C2-TEST"},
		Attachments: []umaispool.AttachmentReader{
			{Name: "raw.bin", MediaType: "", Reader: bytes.NewReader(rawBin)},
			{Name: "doc.pdf", MediaType: "  Application/PDF ", Reader: bytes.NewReader(pdfBytes)},
		},
		Signing: &umaispool.SigningConfig{
			LocalIdentity: "sender-svc",
			PeerIdentity:  "receiver-svc",
			PrivateKey:    privSender,
		},
	})
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	if pubMsg.Attachments[0].MediaType != "" {
		t.Fatalf("Expected absent media_type on raw.bin to remain empty, got %q", pubMsg.Attachments[0].MediaType)
	}
	if pubMsg.Attachments[1].MediaType != "application/pdf" {
		t.Fatalf("Expected normalized media_type application/pdf on doc.pdf, got %q", pubMsg.Attachments[1].MediaType)
	}
	if pubMsg.CreatedAt == nil || pubMsg.AcceptedAt != nil {
		t.Fatalf("Expected outbox message to set CreatedAt only, got CreatedAt=%v AcceptedAt=%v", pubMsg.CreatedAt, pubMsg.AcceptedAt)
	}

	storeRecv, _ := umaispool.NewStorage(receiverDir, 10*1024*1024)
	_ = storeRecv.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "receiver-svc",
		PeerIdentity:  "sender-svc",
		PrivateKey:    privReceiver,
		PeerPublicKey: pubSender,
	})
	handlerRecv, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:              storeRecv,
		RoutePrefix:          "/api",
		AllowedServerOrigins: []string{"https://receiver.example.org"},
		Authorizer: func(_ *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
			return umaispool.Principal{Subject: "tester"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	postInbox := func(id string, sig string, metaField *string, extraMetaField *string, files []struct {
		name string
		body []byte
	}) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("id", id)
		pJSON, _ := json.Marshal(pubMsg.Payload)
		_ = mw.WriteField("payload", string(pJSON))
		if sig != "" {
			_ = mw.WriteField("signature", sig)
		}
		if metaField != nil {
			_ = mw.WriteField("attachment_meta", *metaField)
		}
		if extraMetaField != nil {
			_ = mw.WriteField("attachment_meta", *extraMetaField)
		}
		for _, f := range files {
			part, _ := mw.CreateFormFile("attachments", f.name)
			_, _ = part.Write(f.body)
		}
		_ = mw.Close()

		req, _ := http.NewRequest("POST", "/api/inbox", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Origin", "https://receiver.example.org")
		rec := httptest.NewRecorder()
		handlerRecv.ServeHTTP(rec, req)
		return rec
	}

	bothFiles := []struct {
		name string
		body []byte
	}{
		{name: "raw.bin", body: rawBin},
		{name: "doc.pdf", body: pdfBytes},
	}

	// 2a. Reject missing attachment_meta when attachments are present
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, nil, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 when attachment_meta is omitted with attachments, got %d", rec.Code)
	}

	// 2b. Reject missing entry in attachment_meta (1 entry for 2 attachments)
	missingEntry := `[{"name":"raw.bin"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &missingEntry, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 when attachment_meta is missing an entry, got %d", rec.Code)
	}

	// 2c. Reject unexpected extra entry in attachment_meta (3 entries for 2 attachments)
	extraEntry := `[{"name":"raw.bin"},{"name":"doc.pdf","media_type":"application/pdf"},{"name":"ghost.txt"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &extraEntry, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 when attachment_meta has extra entries, got %d", rec.Code)
	}

	// 2d. Reject duplicate names in attachment_meta
	dupEntry := `[{"name":"raw.bin"},{"name":"raw.bin"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &dupEntry, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 on duplicate names in attachment_meta, got %d", rec.Code)
	}

	// 2e. Reject unknown JSON field in attachment_meta & multiple attachment_meta form values
	unknownField := `[{"name":"raw.bin","extra":1},{"name":"doc.pdf","media_type":"application/pdf"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &unknownField, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 on unknown JSON field in attachment_meta, got %d", rec.Code)
	}
	validMeta := `[{"name":"raw.bin"},{"name":"doc.pdf","media_type":"application/pdf"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &validMeta, &validMeta, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 on multiple attachment_meta form fields, got %d", rec.Code)
	}

	// 2f. Reject oversized attachment_meta (> 64 KiB)
	oversized := `[{"name":"` + strings.Repeat("x", umaispool.MaxAttachmentMetaBytes+10) + `"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &oversized, nil, bothFiles[:1]); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 on oversized attachment_meta, got %d", rec.Code)
	}

	// 2g. Reject tampered media_type (changing absent "" -> "application/octet-stream", or stripping "application/pdf" -> "")
	tamperedAddType := `[{"name":"raw.bin","media_type":"application/octet-stream"},{"name":"doc.pdf","media_type":"application/pdf"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &tamperedAddType, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 when absent media_type is tampered to application/octet-stream, got %d", rec.Code)
	}
	tamperedStripType := `[{"name":"raw.bin"},{"name":"doc.pdf"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &tamperedStripType, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 when declared media_type is stripped, got %d", rec.Code)
	}
	tamperedSwapType := `[{"name":"raw.bin"},{"name":"doc.pdf","media_type":"text/html"}]`
	if rec := postInbox(pubMsg.ID, pubMsg.Signature, &tamperedSwapType, nil, bothFiles); rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 when media_type is tampered to text/html, got %d", rec.Code)
	}
	if storeRecv.IsAccepted(pubMsg.ID) {
		t.Fatalf("Tampered media_type requests must never mark message accepted")
	}

	// 2h. Accept valid request (also testing case-normalization on incoming "APPLICATION/PDF")
	upperCaseMeta := `[{"name":"raw.bin"},{"name":"doc.pdf","media_type":"APPLICATION/PDF"}]`
	okRec := postInbox(pubMsg.ID, pubMsg.Signature, &upperCaseMeta, nil, bothFiles)
	if okRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on valid signed C2 upload, got %d: %s", okRec.Code, okRec.Body.String())
	}

	inboxMsg, err := storeRecv.GetInboxMessage(pubMsg.ID)
	if err != nil {
		t.Fatalf("GetInboxMessage: %v", err)
	}
	if inboxMsg.CreatedAt != nil || inboxMsg.AcceptedAt == nil {
		t.Fatalf("Expected inbox message to set AcceptedAt (UTC) and omit CreatedAt, got CreatedAt=%v AcceptedAt=%v", inboxMsg.CreatedAt, inboxMsg.AcceptedAt)
	}
	if inboxMsg.Attachments[0].MediaType != "" || inboxMsg.Attachments[1].MediaType != "application/pdf" {
		t.Fatalf("Unexpected stored inbox attachment media_type values: %+v", inboxMsg.Attachments)
	}

	// Generic HTTP attachment download MUST still serve Content-Type: application/octet-stream even when media_type is application/pdf!
	dlReq, _ := http.NewRequest("GET", "/api/inbox/"+pubMsg.ID+"/attachments/doc.pdf", nil)
	dlRec := httptest.NewRecorder()
	handlerRecv.ServeHTTP(dlRec, dlReq)
	if dlRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK downloading doc.pdf, got %d", dlRec.Code)
	}
	if ct := dlRec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Generic attachment download MUST remain application/octet-stream regardless of declared media_type, got %q", ct)
	}
}

type partialFailReader struct {
	prefix []byte
	read   bool
}

func (r *partialFailReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		n := copy(p, r.prefix)
		return n, nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestDuplicateContentVerification_Ordinary_PendingCommit_And_DeletedInbox(t *testing.T) {
	tmpDir := t.TempDir()
	absTmpDir, _ := filepath.Abs(tmpDir)

	pubSender, privSender, _ := ed25519.GenerateKey(rand.Reader)
	_, privRecv, _ := ed25519.GenerateKey(rand.Reader)

	store, err := umaispool.NewStorage(absTmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if err := store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "recv-app",
		PeerIdentity:  "send-app",
		PrivateKey:    privRecv,
		PeerPublicKey: pubSender,
	}); err != nil {
		t.Fatalf("SetSigningConfig: %v", err)
	}

	handler, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:              store,
		RoutePrefix:          "/api",
		AllowedServerOrigins: []string{"https://recv.example.org"},
		Authorizer: func(_ *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
			return umaispool.Principal{Subject: "op"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	signHelper := func(id string, payload any, name string, body []byte, mediaType string) string {
		h := sha256.Sum256(body)
		sig, sErr := umaispool.SignPutMessage(privSender, "send-app", "recv-app", id, payload, []umaispool.AttachmentInfo{
			{Name: name, Size: int64(len(body)), SHA256: hex.EncodeToString(h[:]), MediaType: mediaType},
		})
		if sErr != nil {
			t.Fatalf("SignPutMessage: %v", sErr)
		}
		return sig
	}

	msgID := "dup-check-1"
	origPayload := map[string]any{"version": 1}
	origBytes := []byte("authentic-contract-v1")
	origSig := signHelper(msgID, origPayload, "contract.pdf", origBytes, "application/pdf")

	conflictPayload := map[string]any{"version": 2}
	conflictBytes := []byte("conflicting-contract-v2")
	// Validly signed by the real sender key for the SAME ID, but DIFFERENT content!
	conflictSig := signHelper(msgID, conflictPayload, "contract.pdf", conflictBytes, "application/pdf")

	// =========================================================================
	// Phase 1: Pending Commit Duplicate Verification (dataDir sync fault active)
	// =========================================================================
	store.SetSyncDirForTesting(func(dirPath string) error {
		if dirPath == absTmpDir {
			return errors.New("injected dataDir sync failure")
		}
		return nil
	})

	if _, err := store.AcceptSignedMessage(msgID, origPayload, []umaispool.AttachmentReader{
		{Name: "contract.pdf", MediaType: "application/pdf", Reader: bytes.NewReader(origBytes)},
	}, origSig); err == nil {
		t.Fatalf("Expected initial AcceptSignedMessage to fail while dataDir sync is failing")
	}

	// 1a. Conflicting content during pendingCommits MUST fail with ErrConflictingDuplicate (not overwrite pending commit)
	if _, err := store.AcceptSignedMessage(msgID, conflictPayload, []umaispool.AttachmentReader{
		{Name: "contract.pdf", MediaType: "application/pdf", Reader: bytes.NewReader(conflictBytes)},
	}, conflictSig); !errors.Is(err, umaispool.ErrConflictingDuplicate) {
		t.Fatalf("Expected ErrConflictingDuplicate during pendingCommits for conflicting validly-signed duplicate, got %v", err)
	}

	// 1b. Incomplete/failed attachment read during pendingCommits MUST report read error, never acceptance
	if _, err := store.AcceptSignedMessage(msgID, origPayload, []umaispool.AttachmentReader{
		{Name: "contract.pdf", MediaType: "application/pdf", Reader: &partialFailReader{prefix: origBytes[:5]}},
	}, origSig); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Expected ErrUnexpectedEOF on incomplete read during pendingCommits, got %v", err)
	}

	// Clear sync fault and finalize via matching duplicate retry
	store.SetSyncDirForTesting(nil)
	time.Sleep(15 * time.Millisecond) // Ensure wall-clock advances so we prove original AcceptedAt was preserved!

	committedMsg, err := store.AcceptSignedMessage(msgID, origPayload, []umaispool.AttachmentReader{
		{Name: "contract.pdf", MediaType: "application/pdf", Reader: bytes.NewReader(origBytes)},
	}, origSig)
	if err != nil {
		t.Fatalf("Expected matching duplicate retry to finalize pending commit cleanly, got %v", err)
	}
	origAcceptedAt := *committedMsg.AcceptedAt
	origReceipt := committedMsg.AckReceipt

	// Verify accepted.json schema on disk: UTC RFC3339 accepted_at, ack_receipt, and 64-hex digest
	rawAcceptedJSON, err := os.ReadFile(filepath.Join(absTmpDir, "accepted.json"))
	if err != nil {
		t.Fatalf("ReadFile accepted.json: %v", err)
	}
	if !strings.Contains(string(rawAcceptedJSON), `"accepted_at":`) || !strings.Contains(string(rawAcceptedJSON), `Z"`) {
		t.Fatalf("Expected UTC RFC3339 accepted_at in accepted.json, got:\n%s", string(rawAcceptedJSON))
	}
	recOnDisk, ok := store.GetAcceptedRecord(msgID)
	if !ok || len(recOnDisk.Digest) != 64 || !recOnDisk.AcceptedAt.Equal(origAcceptedAt) || recOnDisk.AckReceipt != origReceipt {
		t.Fatalf("Unexpected AcceptedRecord: ok=%v rec=%+v", ok, recOnDisk)
	}

	// =========================================================================
	// Phase 2: Ordinary Duplicate Verification (inbox/ directory present)
	// =========================================================================
	time.Sleep(15 * time.Millisecond)

	// 2a. Matching duplicate via HTTP handler -> 200 OK with exact original accepted_at and ack_receipt
	sendHTTP := func(p any, body []byte, sig string, mediaType string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("id", msgID)
		pJSON, _ := json.Marshal(p)
		_ = mw.WriteField("payload", string(pJSON))
		_ = mw.WriteField("signature", sig)
		metaJSON, _ := json.Marshal([]umaispool.AttachmentMetaEntry{{Name: "contract.pdf", MediaType: mediaType}})
		_ = mw.WriteField("attachment_meta", string(metaJSON))
		part, _ := mw.CreateFormFile("attachments", "contract.pdf")
		_, _ = part.Write(body)
		_ = mw.Close()

		req, _ := http.NewRequest("POST", "/api/inbox", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Origin", "https://recv.example.org")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	dupOK := sendHTTP(origPayload, origBytes, origSig, "application/pdf")
	if dupOK.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on matching duplicate PUT, got %d: %s", dupOK.Code, dupOK.Body.String())
	}
	var dupResp struct {
		Accepted   bool      `json:"accepted"`
		AcceptedAt time.Time `json:"accepted_at"`
		AckReceipt string    `json:"ack_receipt"`
	}
	_ = json.Unmarshal(dupOK.Body.Bytes(), &dupResp)
	if !dupResp.Accepted || dupResp.AckReceipt != origReceipt || !dupResp.AcceptedAt.Equal(origAcceptedAt) {
		t.Fatalf("Matching duplicate must return original receipt & timestamp: got (%v, %q), want (%v, %q)",
			dupResp.AcceptedAt, dupResp.AckReceipt, origAcceptedAt, origReceipt)
	}

	// 2b. Conflicting duplicate via HTTP handler -> 409 Conflict without modifying existing inbox/ or accepted.json!
	dupConflict := sendHTTP(conflictPayload, conflictBytes, conflictSig, "application/pdf")
	if dupConflict.Code != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict on conflicting duplicate with same ID, got %d: %s", dupConflict.Code, dupConflict.Body.String())
	}
	attPath, _ := store.GetInboxAttachmentPath(msgID, "contract.pdf")
	stillOrig, _ := os.ReadFile(attPath)
	if !bytes.Equal(stillOrig, origBytes) {
		t.Fatalf("Conflicting duplicate modified existing inbox attachment!")
	}

	// 2c. Incomplete/failed attachment read on ordinary duplicate -> error, never acceptance!
	if _, err := store.AcceptSignedMessage(msgID, origPayload, []umaispool.AttachmentReader{
		{Name: "contract.pdf", MediaType: "application/pdf", Reader: &partialFailReader{prefix: origBytes[:4]}},
	}, origSig); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Expected ErrUnexpectedEOF on failed read during ordinary duplicate check, got %v", err)
	}

	// =========================================================================
	// Phase 3: Deleted-Inbox Duplicate Verification (hot-folder consumer removed inbox/ dir)
	// =========================================================================
	dirKey, _ := umaispool.StorageDirKey(msgID)
	if err := os.RemoveAll(filepath.Join(absTmpDir, "inbox", dirKey)); err != nil {
		t.Fatalf("RemoveAll inbox dir: %v", err)
	}

	// 3a. Conflicting duplicate after inbox deletion -> 409 Conflict, inbox remains deleted, original record untouched!
	dupConflictAfterDelete := sendHTTP(conflictPayload, conflictBytes, conflictSig, "application/pdf")
	if dupConflictAfterDelete.Code != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict on conflicting duplicate after inbox deletion, got %d", dupConflictAfterDelete.Code)
	}

	// 3b. Failed/incomplete read after inbox deletion -> error, never acceptance!
	if _, err := store.AcceptSignedMessage(msgID, origPayload, []umaispool.AttachmentReader{
		{Name: "contract.pdf", MediaType: "application/pdf", Reader: &partialFailReader{prefix: origBytes[:3]}},
	}, origSig); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Expected ErrUnexpectedEOF on failed read after inbox deletion, got %v", err)
	}

	// 3c. Matching duplicate after inbox deletion -> 200 OK with exact original accepted_at & ack_receipt, without recreating inbox/!
	dupMatchAfterDelete := sendHTTP(origPayload, origBytes, origSig, "application/pdf")
	if dupMatchAfterDelete.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on matching duplicate after inbox deletion, got %d: %s", dupMatchAfterDelete.Code, dupMatchAfterDelete.Body.String())
	}
	var dupAfterDelResp struct {
		Accepted   bool      `json:"accepted"`
		AcceptedAt time.Time `json:"accepted_at"`
		AckReceipt string    `json:"ack_receipt"`
	}
	_ = json.Unmarshal(dupMatchAfterDelete.Body.Bytes(), &dupAfterDelResp)
	if !dupAfterDelResp.Accepted || dupAfterDelResp.AckReceipt != origReceipt || !dupAfterDelResp.AcceptedAt.Equal(origAcceptedAt) {
		t.Fatalf("Expected preserved receipt & AcceptedAt after inbox deletion, got %+v", dupAfterDelResp)
	}
	if _, err := os.Stat(filepath.Join(absTmpDir, "inbox", dirKey)); !os.IsNotExist(err) {
		t.Fatalf("Duplicate acceptance check must not recreate deleted inbox directory!")
	}

	// =========================================================================
	// Phase 4: Unsigned Mode Duplicate Content Verification
	// =========================================================================
	unsignedStore, _ := umaispool.NewStorage(t.TempDir(), 10*1024*1024)
	uMsg, err := unsignedStore.AcceptMessage("u-msg-1", map[string]int{"x": 1}, []umaispool.AttachmentReader{
		{Name: "a.txt", MediaType: "text/plain", Reader: bytes.NewReader([]byte("v1"))},
	})
	if err != nil {
		t.Fatalf("Unsigned AcceptMessage: %v", err)
	}
	// Matching unsigned duplicate succeeds and preserves AcceptedAt
	uDup, err := unsignedStore.AcceptMessage("u-msg-1", map[string]int{"x": 1}, []umaispool.AttachmentReader{
		{Name: "a.txt", MediaType: "text/plain", Reader: bytes.NewReader([]byte("v1"))},
	})
	if err != nil || !uDup.AcceptedAt.Equal(*uMsg.AcceptedAt) {
		t.Fatalf("Expected matching unsigned duplicate to succeed with original AcceptedAt, got err=%v", err)
	}
	// Conflicting unsigned duplicate (different attachment bytes OR different media_type) fails with ErrConflictingDuplicate!
	if _, err := unsignedStore.AcceptMessage("u-msg-1", map[string]int{"x": 1}, []umaispool.AttachmentReader{
		{Name: "a.txt", MediaType: "text/plain", Reader: bytes.NewReader([]byte("v2"))},
	}); !errors.Is(err, umaispool.ErrConflictingDuplicate) {
		t.Fatalf("Expected ErrConflictingDuplicate in unsigned mode on modified bytes, got %v", err)
	}
	if _, err := unsignedStore.AcceptMessage("u-msg-1", map[string]int{"x": 1}, []umaispool.AttachmentReader{
		{Name: "a.txt", MediaType: "text/csv", Reader: bytes.NewReader([]byte("v1"))},
	}); !errors.Is(err, umaispool.ErrConflictingDuplicate) {
		t.Fatalf("Expected ErrConflictingDuplicate in unsigned mode on modified media_type, got %v", err)
	}
}
