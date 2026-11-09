package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/umai-protocol/umai/internal/demoapp"
	"github.com/umai-protocol/umai/pkg/umaispool"
)

func TestSpoolHandler_MultipartSpillOver4MiBAndSizeLimits(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)

	// Configure receiver with 8 MiB per-attachment limit (> 4 MiB DefaultMultipartMemory)
	const maxUpload = 8 * 1024 * 1024
	storeB, err := umaispool.NewStorage(t.TempDir(), maxUpload)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if err := storeB.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	}); err != nil {
		t.Fatalf("SetSigningConfig: %v", err)
	}

	handlerB, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:              storeB,
		RoutePrefix:          "/api",
		AllowedServerOrigins: []string{"https://app-b.example.org"},
		Authorizer: func(_ *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
			return umaispool.Principal{Subject: "tester", SessionKey: "sess-1"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// 1. 5 MiB attachment (> DefaultMultipartMemory = 4 MiB) spills to temp file, verifies, commits, and cleans up
	fiveMiB := bytes.Repeat([]byte("UMAI-5MIB-BLOCK-"), (5*1024*1024)/16)
	fiveHash := sha256.Sum256(fiveMiB)
	msgID := "msg-5mib-spill-001"
	payload := map[string]any{"kind": "large-bundle"}
	sig5, err := umaispool.SignPutMessage(privA, "app-a", "app-b", msgID, payload, []umaispool.AttachmentInfo{
		{
			Name:      "archive.bin",
			Size:      int64(len(fiveMiB)),
			SHA256:    hex.EncodeToString(fiveHash[:]),
			MediaType: "application/octet-stream",
		},
	})
	if err != nil {
		t.Fatalf("SignPutMessage: %v", err)
	}

	postMultipart := func(id string, sig string, filename string, mediaType string, data []byte) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("id", id)
		pBytes, _ := json.Marshal(payload)
		_ = mw.WriteField("payload", string(pBytes))
		_ = mw.WriteField("signature", sig)
		metaJSON, _ := json.Marshal([]umaispool.AttachmentMetaEntry{
			{Name: filename, MediaType: mediaType},
		})
		_ = mw.WriteField("attachment_meta", string(metaJSON))
		fw, _ := mw.CreateFormFile("attachments", filename)
		_, _ = fw.Write(data)
		_ = mw.Close()

		req, _ := http.NewRequest("POST", "/api/inbox", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Origin", "https://app-b.example.org")
		rec := httptest.NewRecorder()
		handlerB.ServeHTTP(rec, req)
		return rec
	}

	rec5 := postMultipart(msgID, sig5, "archive.bin", "application/octet-stream", fiveMiB)
	if rec5.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for 5 MiB spilled multipart upload, got %d: %s", rec5.Code, rec5.Body.String())
	}
	inMsg, err := storeB.GetInboxMessage(msgID)
	if err != nil || len(inMsg.Attachments) != 1 || inMsg.Attachments[0].Size != int64(len(fiveMiB)) {
		t.Fatalf("Expected 5 MiB attachment in inbox, got msg=%+v err=%v", inMsg, err)
	}

	// 2. Attachment exceeding MaxUploadSize (9 MiB > 8 MiB, within MaxBytesReader envelope) -> 413 Request Entity Too Large
	nineMiB := bytes.Repeat([]byte("A"), 9*1024*1024)
	nineHash := sha256.Sum256(nineMiB)
	sig9, _ := umaispool.SignPutMessage(privA, "app-a", "app-b", "msg-9mib-too-large", payload, []umaispool.AttachmentInfo{
		{
			Name:   "oversize.bin",
			Size:   int64(len(nineMiB)),
			SHA256: hex.EncodeToString(nineHash[:]),
		},
	})
	rec9 := postMultipart("msg-9mib-too-large", sig9, "oversize.bin", "", nineMiB)
	if rec9.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Request Entity Too Large for 9 MiB attachment (> 8 MiB limit), got %d: %s", rec9.Code, rec9.Body.String())
	}

	// 3. Total HTTP request body exceeding MaxUploadSize + MultipartEnvelopeOverhead (MaxBytesReader limit) -> 413
	storeTiny, err := umaispool.NewStorage(t.TempDir(), 64*1024)
	if err != nil {
		t.Fatalf("NewStorage tiny: %v", err)
	}
	_ = storeTiny.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	})
	handlerTiny, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:              storeTiny,
		RoutePrefix:          "/api",
		AllowedServerOrigins: []string{"https://app-b.example.org"},
		Authorizer: func(_ *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
			return umaispool.Principal{Subject: "tester"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler tiny: %v", err)
	}

	hugeEnvelope := bytes.Repeat([]byte("X"), int(64*1024+umaispool.MultipartEnvelopeOverhead+512*1024))
	var hugeBody bytes.Buffer
	hmw := multipart.NewWriter(&hugeBody)
	_ = hmw.WriteField("id", "msg-huge-envelope")
	_ = hmw.WriteField("attachment_meta", `[{"name":"huge.bin"}]`)
	hfw, _ := hmw.CreateFormFile("attachments", "huge.bin")
	_, _ = hfw.Write(hugeEnvelope)
	_ = hmw.Close()

	hugeReq, _ := http.NewRequest("POST", "/api/inbox", &hugeBody)
	hugeReq.Header.Set("Content-Type", hmw.FormDataContentType())
	hugeReq.Header.Set("Origin", "https://app-b.example.org")
	hugeRec := httptest.NewRecorder()
	handlerTiny.ServeHTTP(hugeRec, hugeReq)
	if hugeRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Request Entity Too Large when MaxBytesReader trips during ParseMultipartForm, got %d: %s", hugeRec.Code, hugeRec.Body.String())
	}

	// 4. Oversized JSON body on POST /inbox/acceptance (> 256 KiB) -> 413 Request Entity Too Large
	bigJSON := `{"ids":["` + strings.Repeat("a", 300*1024) + `"]}`
	accReq, _ := http.NewRequest("POST", "/api/inbox/acceptance", strings.NewReader(bigJSON))
	accReq.Header.Set("Content-Type", "application/json")
	accReq.Header.Set("Origin", "https://app-b.example.org")
	accRec := httptest.NewRecorder()
	handlerB.ServeHTTP(accRec, accReq)
	if accRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Request Entity Too Large on oversized POST /inbox/acceptance body, got %d: %s", accRec.Code, accRec.Body.String())
	}

	// 5. Demo POST /api/docs also enforces 413 on oversized upload
	cfgDemo := demoapp.DefaultConfig("app-a")
	cfgDemo.AllowDemoDefaults = true
	cfgDemo.DataDir = t.TempDir()
	cfgDemo.MaxUploadSize = 1024 // 1 KiB
	srvDemo, err := demoapp.NewServer(cfgDemo, "")
	if err != nil {
		t.Fatalf("demoapp.NewServer: %v", err)
	}
	sessID, ok := srvDemo.Auth().Authenticate(cfgDemo.AuthUsername, cfgDemo.AuthPassword)
	if !ok {
		t.Fatalf("Authenticate failed")
	}
	var docBuf bytes.Buffer
	dmw := multipart.NewWriter(&docBuf)
	dfw, _ := dmw.CreateFormFile("file", "too-big.txt")
	_, _ = dfw.Write(bytes.Repeat([]byte("Z"), 4096))
	_ = dmw.Close()
	docReq, _ := http.NewRequest("POST", "/api/docs", &docBuf)
	docReq.Header.Set("Content-Type", dmw.FormDataContentType())
	docReq.Header.Set("Origin", "http://"+cfgDemo.ListenAddr)
	docReq.AddCookie(&http.Cookie{Name: cfgDemo.CookieName, Value: sessID})
	docRec := httptest.NewRecorder()
	srvDemo.Handler().ServeHTTP(docRec, docReq)
	if docRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Request Entity Too Large on oversized demo POST /api/docs, got %d: %s", docRec.Code, docRec.Body.String())
	}

	_ = pubB
}

func TestSpoolHandler_ErrorStatusClassification_400_404_409_500(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)

	dataDir := t.TempDir()
	storeB, err := umaispool.NewStorage(dataDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if err := storeB.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	}); err != nil {
		t.Fatalf("SetSigningConfig: %v", err)
	}

	handlerB, err := umaispool.NewHandler(umaispool.HandlerConfig{
		Storage:              storeB,
		RoutePrefix:          "/api",
		AllowedServerOrigins: []string{"https://app-b.example.org"},
		Authorizer: func(_ *http.Request, _ umaispool.Operation) (umaispool.Principal, error) {
			return umaispool.Principal{Subject: "tester"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	sendInbox := func(id string, payload map[string]any, sig string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("id", id)
		pBytes, _ := json.Marshal(payload)
		_ = mw.WriteField("payload", string(pBytes))
		_ = mw.WriteField("signature", sig)
		_ = mw.Close()

		req, _ := http.NewRequest("POST", "/api/inbox", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Origin", "https://app-b.example.org")
		rec := httptest.NewRecorder()
		handlerB.ServeHTTP(rec, req)
		return rec
	}

	// 1. Invalid ID -> 400 Bad Request
	recBadID := sendInbox("../bad-id", map[string]any{"x": 1}, "deadbeef")
	if recBadID.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for invalid ID, got %d", recBadID.Code)
	}

	// 2. Forged signature -> 400 Bad Request
	recBadSig := sendInbox("valid-id-001", map[string]any{"x": 1}, strings.Repeat("ab", 64))
	if recBadSig.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for invalid signature, got %d", recBadSig.Code)
	}

	// 3. Missing inbox message -> 404 Not Found
	getMissingReq, _ := http.NewRequest("GET", "/api/inbox/non-existent-id", nil)
	getMissingRec := httptest.NewRecorder()
	handlerB.ServeHTTP(getMissingRec, getMissingReq)
	if getMissingRec.Code != http.StatusNotFound {
		t.Fatalf("Expected 404 Not Found for missing inbox message, got %d", getMissingRec.Code)
	}

	// 4. Inject directory fsync failure on dataDir -> POST /inbox and POST /inbox/acceptance MUST return 500 (not 400),
	//    and MUST NOT leak internal filesystem paths in the HTTP error body.
	absDataDir := storeB.DataDir()
	storeB.SetSyncDirForTesting(func(dir string) error {
		if dir == absDataDir {
			return errors.New("simulated EIO syncing " + absDataDir)
		}
		return umaispool.SyncDir(dir)
	})

	payload1 := map[string]any{"seq": 1}
	sig1, err := umaispool.SignPutMessage(privA, "app-a", "app-b", "durability-err-001", payload1, nil)
	if err != nil {
		t.Fatalf("SignPutMessage: %v", err)
	}

	rec500 := sendInbox("durability-err-001", payload1, sig1)
	if rec500.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 Internal Server Error on dataDir fsync failure during POST /inbox, got %d: %s", rec500.Code, rec500.Body.String())
	}
	if strings.Contains(rec500.Body.String(), absDataDir) {
		t.Fatalf("500 response leaked internal dataDir path %q: %s", absDataDir, rec500.Body.String())
	}

	// Querying acceptance while pendingCommits flush still fails must ALSO return 500 (not 400 and never accepted:true)
	accReq, _ := http.NewRequest("POST", "/api/inbox/acceptance", strings.NewReader(`{"ids":["durability-err-001"]}`))
	accReq.Header.Set("Content-Type", "application/json")
	accReq.Header.Set("Origin", "https://app-b.example.org")
	accRec := httptest.NewRecorder()
	handlerB.ServeHTTP(accRec, accReq)
	if accRec.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 Internal Server Error on unresolved pendingCommit during POST /inbox/acceptance, got %d: %s", accRec.Code, accRec.Body.String())
	}
	if strings.Contains(accRec.Body.String(), absDataDir) {
		t.Fatalf("500 response leaked internal dataDir path %q: %s", absDataDir, accRec.Body.String())
	}

	// Restore SyncDir -> recovery succeeds with 200 OK, and subsequent conflicting payload under same ID returns 409 Conflict
	storeB.SetSyncDirForTesting(nil)
	recRecovered := sendInbox("durability-err-001", payload1, sig1)
	if recRecovered.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK after restoring SyncDir, got %d: %s", recRecovered.Code, recRecovered.Body.String())
	}

	payloadConflict := map[string]any{"seq": 2}
	sigConflict, _ := umaispool.SignPutMessage(privA, "app-a", "app-b", "durability-err-001", payloadConflict, nil)
	rec409 := sendInbox("durability-err-001", payloadConflict, sigConflict)
	if rec409.Code != http.StatusConflict {
		t.Fatalf("Expected 409 Conflict on conflicting duplicate, got %d: %s", rec409.Code, rec409.Body.String())
	}
}
