package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/umai-protocol/umai/pkg/umaispool"
)

func TestPublish_StatelessProducerOwnership_And_EndToEndTransfer(t *testing.T) {
	dirA := filepath.Join(t.TempDir(), "spool-a")
	dirB := filepath.Join(t.TempDir(), "spool-b")

	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)

	// 1. Fail-closed checks before publishing
	if _, err := umaispool.Publish(umaispool.PublishRequest{
		DataDir: dirA,
		Payload: map[string]string{"k": "v"},
	}); !errors.Is(err, umaispool.ErrSigningNotConfigured) {
		t.Fatalf("Expected ErrSigningNotConfigured when Signing is nil and AllowUnsigned is false, got %v", err)
	}

	// 2. Stateless Publish into fresh dirA BEFORE any Storage server has ever started
	attContent := []byte("Signed contract PDF bytes from external batch producer")
	published, err := umaispool.Publish(umaispool.PublishRequest{
		DataDir: dirA,
		ID:      "batch-job-2026-0001",
		Payload: map[string]any{"invoice": "INV-0001", "amount": 4200},
		Attachments: []umaispool.AttachmentReader{
			{Name: "invoice.pdf", Reader: bytes.NewReader(attContent)},
		},
		Signing: &umaispool.SigningConfig{
			LocalIdentity: "billing-app",
			PeerIdentity:  "accounting-app",
			PrivateKey:    privA,
			// Note: PeerPublicKey intentionally omitted — offline producer only needs its own signing key!
		},
	})
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	if published.ID != "batch-job-2026-0001" || published.Signature == "" {
		t.Fatalf("Unexpected published message metadata: %+v", published)
	}

	// Verify producer NEVER created server-owned .staging, .committing, inbox, or accepted.json,
	// and left prepare/ completely clean after atomic rename.
	for _, serverOwned := range []string{".staging", ".committing", "inbox", "accepted.json"} {
		if _, err := os.Stat(filepath.Join(dirA, serverOwned)); !os.IsNotExist(err) {
			t.Fatalf("Stateless Publish must not create server-owned %s, stat err=%v", serverOwned, err)
		}
	}
	prepEntries, err := os.ReadDir(filepath.Join(dirA, "prepare"))
	if err != nil || len(prepEntries) != 0 {
		t.Fatalf("Expected empty prepare/ after completed Publish, got %d entries (err=%v)", len(prepEntries), err)
	}

	// 3. Oversized attachment fails cleanly and leaves prepare/ empty
	if _, err := umaispool.Publish(umaispool.PublishRequest{
		DataDir:           dirA,
		ID:                "oversized-job",
		MaxAttachmentSize: 16,
		Attachments: []umaispool.AttachmentReader{
			{Name: "big.bin", Reader: bytes.NewReader(bytes.Repeat([]byte("X"), 32))},
		},
		AllowUnsigned: true,
	}); !errors.Is(err, umaispool.ErrFileTooLarge) {
		t.Fatalf("Expected ErrFileTooLarge, got %v", err)
	}
	prepEntries, _ = os.ReadDir(filepath.Join(dirA, "prepare"))
	if len(prepEntries) != 0 {
		t.Fatalf("Expected failed Publish to clean up prepare/, got %d entries", len(prepEntries))
	}

	// 4. Start Sender & Receiver Storage instances and verify end-to-end signed transfer + ACK deletion
	storeA, err := umaispool.NewStorage(dirA, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage A: %v", err)
	}
	if err := storeA.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "billing-app",
		PeerIdentity:  "accounting-app",
		PrivateKey:    privA,
		PeerPublicKey: pubB,
	}); err != nil {
		t.Fatalf("SetSigningConfig A: %v", err)
	}

	storeB, err := umaispool.NewStorage(dirB, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage B: %v", err)
	}
	if err := storeB.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "accounting-app",
		PeerIdentity:  "billing-app",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	}); err != nil {
		t.Fatalf("SetSigningConfig B: %v", err)
	}

	outboxMsgs, err := storeA.ListOutbox()
	if err != nil || len(outboxMsgs) != 1 || outboxMsgs[0].ID != "batch-job-2026-0001" {
		t.Fatalf("Expected storeA to discover published message, got %v (err=%v)", outboxMsgs, err)
	}
	attPath, err := storeA.GetOutboxAttachmentPath("batch-job-2026-0001", "invoice.pdf")
	if err != nil {
		t.Fatalf("GetOutboxAttachmentPath: %v", err)
	}
	attBytesOnDisk, _ := os.ReadFile(attPath)

	accepted, err := storeB.AcceptSignedMessage(
		outboxMsgs[0].ID,
		outboxMsgs[0].Payload,
		[]umaispool.AttachmentReader{{Name: "invoice.pdf", Reader: bytes.NewReader(attBytesOnDisk)}},
		outboxMsgs[0].Signature,
	)
	if err != nil {
		t.Fatalf("AcceptSignedMessage on B failed: %v", err)
	}
	if err := storeA.AcknowledgeMessagesVerified([]string{accepted.ID}, map[string]string{accepted.ID: accepted.AckReceipt}); err != nil {
		t.Fatalf("AcknowledgeMessagesVerified on A failed: %v", err)
	}
	remaining, _ := storeA.ListOutbox()
	if len(remaining) != 0 {
		t.Fatalf("Expected outbox to be empty after verified ACK, got %d", len(remaining))
	}
}

func TestPublish_ConcurrentSameID_NeverOverwritesWinner(t *testing.T) {
	dataDir := t.TempDir()
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)

	const workers = 16
	const sharedID = "concurrent-same-id-race"

	startCh := make(chan struct{})
	type result struct {
		workerIdx int
		msg       *umaispool.Message
		body      []byte
		err       error
	}
	results := make(chan result, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf("attachment-from-producer-%02d-%s", idx, strings.Repeat("Z", idx*17+5)))
			payload := map[string]any{"worker": idx}
			<-startCh
			msg, err := umaispool.Publish(umaispool.PublishRequest{
				DataDir: dataDir,
				ID:      sharedID,
				Payload: payload,
				Attachments: []umaispool.AttachmentReader{
					{Name: "payload.bin", Reader: bytes.NewReader(body)},
				},
				Signing: &umaispool.SigningConfig{
					LocalIdentity: "producer-node",
					PeerIdentity:  "consumer-node",
					PrivateKey:    privA,
				},
			})
			results <- result{workerIdx: idx, msg: msg, body: body, err: err}
		}(i)
	}

	close(startCh)
	wg.Wait()
	close(results)

	var winners []result
	alreadyPublishedCount := 0
	for r := range results {
		if r.err == nil {
			winners = append(winners, r)
		} else if errors.Is(r.err, umaispool.ErrAlreadyPublished) {
			alreadyPublishedCount++
		} else {
			t.Fatalf("Worker %d failed with unexpected error (expected nil or ErrAlreadyPublished): %v", r.workerIdx, r.err)
		}
	}

	if len(winners) != 1 || alreadyPublishedCount != workers-1 {
		t.Fatalf("Expected exactly 1 winner and %d ErrAlreadyPublished, got %d winners and %d ErrAlreadyPublished",
			workers-1, len(winners), alreadyPublishedCount)
	}

	winner := winners[0]

	// Verify prepare/ has zero leftover directories
	prepEntries, err := os.ReadDir(filepath.Join(dataDir, "prepare"))
	if err != nil || len(prepEntries) != 0 {
		t.Fatalf("Expected 0 leftover entries in prepare/, got %d (err=%v)", len(prepEntries), err)
	}

	// Verify the winning message on disk matches the winning worker's exact payload, attachment bytes, and signature
	storeA, err := umaispool.NewStorage(dataDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	outMsg, err := storeA.GetOutboxMessage(sharedID)
	if err != nil {
		t.Fatalf("GetOutboxMessage: %v", err)
	}
	if outMsg.Signature != winner.msg.Signature {
		t.Fatalf("Winning signature was modified! got %s, want %s", outMsg.Signature, winner.msg.Signature)
	}
	attPath, err := storeA.GetOutboxAttachmentPath(sharedID, "payload.bin")
	if err != nil {
		t.Fatalf("GetOutboxAttachmentPath: %v", err)
	}
	diskBytes, err := os.ReadFile(attPath)
	if err != nil || !bytes.Equal(diskBytes, winner.body) {
		t.Fatalf("Winning attachment bytes corrupted: got %q, want %q", string(diskBytes), string(winner.body))
	}

	// Verify receiver cryptographically accepts the winner without signature mismatch
	storeB, _ := umaispool.NewStorage(t.TempDir(), 10*1024*1024)
	_ = storeB.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "consumer-node",
		PeerIdentity:  "producer-node",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	})
	if _, err := storeB.AcceptSignedMessage(outMsg.ID, outMsg.Payload, []umaispool.AttachmentReader{
		{Name: "payload.bin", Reader: bytes.NewReader(diskBytes)},
	}, outMsg.Signature); err != nil {
		t.Fatalf("Receiver failed to verify winning message signature: %v", err)
	}
}

type gatedReader struct {
	data      []byte
	offset    int
	startedOnce sync.Once
	startedCh chan struct{}
	resumeCh  <-chan struct{}
}

func (g *gatedReader) Read(p []byte) (int, error) {
	g.startedOnce.Do(func() {
		close(g.startedCh)
		<-g.resumeCh
	})
	if g.offset >= len(g.data) {
		return 0, io.EOF
	}
	n := copy(p, g.data[g.offset:])
	g.offset += n
	return n, nil
}

func TestPublish_ConcurrentServerRestart_LeavesPrepareUntouched(t *testing.T) {
	dataDir := t.TempDir()
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, _ = pubA, privA

	// Pre-create a server-owned .staging/ orphan file to confirm NewStorage purges .staging/
	orphanStagingFile := filepath.Join(dataDir, ".staging", "crashed-server-temp.json")
	if err := os.MkdirAll(filepath.Dir(orphanStagingFile), 0700); err != nil {
		t.Fatalf("MkdirAll .staging: %v", err)
	}
	if err := os.WriteFile(orphanStagingFile, []byte("orphan"), 0600); err != nil {
		t.Fatalf("WriteFile orphan: %v", err)
	}

	startedCh := make(chan struct{})
	resumeCh := make(chan struct{})
	attPayload := []byte("producer-staged-while-server-restarts")

	type pubRes struct {
		msg *umaispool.Message
		err error
	}
	doneCh := make(chan pubRes, 1)

	go func() {
		msg, err := umaispool.Publish(umaispool.PublishRequest{
			DataDir: dataDir,
			ID:      "survives-server-restart",
			Payload: map[string]string{"phase": "in-flight-prepare"},
			Attachments: []umaispool.AttachmentReader{
				{
					Name: "report.txt",
					Reader: &gatedReader{
						data:      attPayload,
						startedCh: startedCh,
						resumeCh:  resumeCh,
					},
				},
			},
			Signing: &umaispool.SigningConfig{
				LocalIdentity: "app-producer",
				PeerIdentity:  "app-consumer",
				PrivateKey:    privA,
			},
		})
		doneCh <- pubRes{msg: msg, err: err}
	}()

	// Wait until producer has actively created its staging directory inside <dataDir>/prepare/
	<-startedCh

	prepEntries, err := os.ReadDir(filepath.Join(dataDir, "prepare"))
	if err != nil || len(prepEntries) != 1 {
		t.Fatalf("Expected 1 active staging directory in prepare/, got %d (err=%v)", len(prepEntries), err)
	}

	// Restart server Storage concurrently while producer is paused mid-staging!
	restartedStore, err := umaispool.NewStorage(dataDir, 10*1024*1024)
	if err != nil {
		close(resumeCh)
		t.Fatalf("NewStorage during active prepare/: %v", err)
	}

	// Confirm server startup purged .staging/ orphan, left prepare/ intact, and outbox is still empty
	if _, err := os.Stat(orphanStagingFile); !os.IsNotExist(err) {
		close(resumeCh)
		t.Fatalf("Expected NewStorage to purge .staging/ orphan file, stat err=%v", err)
	}
	prepEntriesAfterRestart, err := os.ReadDir(filepath.Join(dataDir, "prepare"))
	if err != nil || len(prepEntriesAfterRestart) != 1 {
		close(resumeCh)
		t.Fatalf("NewStorage MUST NOT purge prepare/! got %d entries (err=%v)", len(prepEntriesAfterRestart), err)
	}
	outboxBeforeFinish, err := restartedStore.ListOutbox()
	if err != nil || len(outboxBeforeFinish) != 0 {
		close(resumeCh)
		t.Fatalf("Incomplete message in prepare/ must not appear in outbox, got %v", outboxBeforeFinish)
	}

	// Unblock producer and confirm atomic publication into the running server's outbox
	close(resumeCh)
	res := <-doneCh
	if res.err != nil {
		t.Fatalf("Expected producer Publish to succeed after concurrent server restart, got: %v", res.err)
	}

	outboxAfterFinish, err := restartedStore.ListOutbox()
	if err != nil || len(outboxAfterFinish) != 1 || outboxAfterFinish[0].ID != "survives-server-restart" {
		t.Fatalf("Expected running server to see completed message in outbox, got %v (err=%v)", outboxAfterFinish, err)
	}
}

func TestCLI_UmaiSpoolPublish(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "umai-spool")

	buildCmd := exec.Command("go", "build", "-o", binPath, "../cmd/umai-spool")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build cmd/umai-spool: %v\n%s", err, string(out))
	}

	spoolDir := filepath.Join(tmpDir, "spool")
	attFile := filepath.Join(tmpDir, "manifest.xml")
	payloadFile := filepath.Join(tmpDir, "payload.json")
	if err := os.WriteFile(attFile, []byte("<manifest id='42'/>"), 0600); err != nil {
		t.Fatalf("WriteFile att: %v", err)
	}
	if err := os.WriteFile(payloadFile, []byte(`{"document_type":"manifest","items":42}`), 0600); err != nil {
		t.Fatalf("WriteFile payload: %v", err)
	}

	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	privHex := hex.EncodeToString(privA.Seed())

	// 1. Missing signing key without -unsigned must fail closed with exit code 2
	cmdNoKey := exec.Command(binPath, "publish", "-data", spoolDir, "-sender", "svc-a", "-receiver", "svc-b")
	cmdNoKey.Env = append(os.Environ(), "UMAI_SIGNING_PRIVATE_KEY=")
	if err := cmdNoKey.Run(); err == nil {
		t.Fatalf("Expected CLI publish without signing key or -unsigned to fail")
	}

	// 2. Malformed inline JSON payload must fail with exit code 2
	cmdBadJSON := exec.Command(binPath, "publish", "-data", spoolDir, "-unsigned", "-payload", "{bad json")
	if err := cmdBadJSON.Run(); err == nil {
		t.Fatalf("Expected CLI publish with malformed JSON payload to fail")
	}

	// 3. Valid signed publication via env key + payload-file + attachment
	cmdPub := exec.Command(binPath, "publish",
		"-data", spoolDir,
		"-id", "cli-msg-001",
		"-sender", "svc-a",
		"-receiver", "svc-b",
		"-payload-file", payloadFile,
		"-attach", attFile,
	)
	cmdPub.Env = append(os.Environ(), "UMAI_SIGNING_PRIVATE_KEY="+privHex)
	var stdout, stderr bytes.Buffer
	cmdPub.Stdout = &stdout
	cmdPub.Stderr = &stderr
	if err := cmdPub.Run(); err != nil {
		t.Fatalf("CLI publish failed: %v\nstderr: %s", err, stderr.String())
	}

	var published umaispool.Message
	if err := json.Unmarshal(stdout.Bytes(), &published); err != nil {
		t.Fatalf("Decoding CLI stdout JSON: %v\nraw: %s", err, stdout.String())
	}
	if published.ID != "cli-msg-001" || published.Signature == "" || len(published.Attachments) != 1 {
		t.Fatalf("Unexpected CLI published message: %+v", published)
	}

	// 4. Re-publishing the exact same ID via CLI must fail and leave original intact
	cmdDup := exec.Command(binPath, "publish",
		"-data", spoolDir,
		"-id", "cli-msg-001",
		"-sender", "svc-a",
		"-receiver", "svc-b",
		"-payload", `{"tampered":true}`,
	)
	cmdDup.Env = append(os.Environ(), "UMAI_SIGNING_PRIVATE_KEY="+privHex)
	var dupStderr bytes.Buffer
	cmdDup.Stderr = &dupStderr
	if err := cmdDup.Run(); err == nil {
		t.Fatalf("Expected duplicate CLI publish of cli-msg-001 to fail")
	}
	if !strings.Contains(dupStderr.String(), "already published") {
		t.Fatalf("Expected 'already published' error message, got: %s", dupStderr.String())
	}

	// 5. Verify receiver Storage accepts the CLI-published message cryptographically
	storeA, _ := umaispool.NewStorage(spoolDir, 10*1024*1024)
	outMsg, err := storeA.GetOutboxMessage("cli-msg-001")
	if err != nil {
		t.Fatalf("GetOutboxMessage: %v", err)
	}
	attOnDisk, _ := os.ReadFile(filepath.Join(spoolDir, "outbox", mustDirKey(t, "cli-msg-001"), "attachments", "manifest.xml"))

	storeB, _ := umaispool.NewStorage(filepath.Join(tmpDir, "spool-b"), 10*1024*1024)
	_ = storeB.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "svc-b",
		PeerIdentity:  "svc-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	})
	if _, err := storeB.AcceptSignedMessage(outMsg.ID, outMsg.Payload, []umaispool.AttachmentReader{
		{Name: "manifest.xml", Reader: bytes.NewReader(attOnDisk)},
	}, outMsg.Signature); err != nil {
		t.Fatalf("Receiver failed to verify CLI-published message: %v", err)
	}
}

func mustDirKey(t *testing.T, id string) string {
	t.Helper()
	dk, err := umaispool.StorageDirKey(id)
	if err != nil {
		t.Fatalf("StorageDirKey(%s): %v", id, err)
	}
	return dk
}
