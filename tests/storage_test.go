package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/umai-protocol/umai/pkg/umaiserver"
)

func TestStorage_DocumentLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := umaiserver.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Failed to init storage: %v", err)
	}

	content := []byte("Hello, UMAI world! Binary document test.")
	docInfo, err := store.SaveDocument("test_doc.txt", bytes.NewReader(content))
	if err != nil {
		t.Fatalf("Failed to save document: %v", err)
	}

	if docInfo.Name != "test_doc.txt" {
		t.Errorf("Expected filename test_doc.txt, got %s", docInfo.Name)
	}
	if docInfo.Size != int64(len(content)) {
		t.Errorf("Expected size %d, got %d", len(content), docInfo.Size)
	}

	hasher := sha256.New()
	hasher.Write(content)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))
	if docInfo.SHA256 != expectedHash {
		t.Errorf("Hash mismatch: expected %s, got %s", expectedHash, docInfo.SHA256)
	}

	// Verify download path
	path, err := store.GetDocumentPath("test_doc.txt")
	if err != nil {
		t.Fatalf("Failed to get doc path: %v", err)
	}
	readBytes, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(readBytes, content) {
		t.Fatalf("File content read from path differs from saved content")
	}

	// Traversal attack protection
	_, err = store.SaveDocument("../../../etc/passwd", bytes.NewReader(content))
	if err == nil {
		// Even if sanitized to 'passwd', verify it stays within docsDir
		p, err := store.GetDocumentPath("passwd")
		if err == nil && !filepath.HasPrefix(p, filepath.Join(tmpDir, "docs")) {
			t.Errorf("Path escaped docsDir: %s", p)
		}
	}

	_, err = store.GetDocumentPath("../../outside.txt")
	if err == nil {
		t.Errorf("Expected error on directory traversal query")
	}

	// Delete
	if err := store.DeleteDocument("test_doc.txt"); err != nil {
		t.Fatalf("Failed to delete document: %v", err)
	}

	_, err = store.GetDocumentPath("test_doc.txt")
	if err == nil {
		t.Errorf("Expected error retrieving deleted document")
	}
}

func TestStorage_ImmutabilityAndSnapshots(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := umaiserver.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage: %v", err)
	}

	// Create original document in docs/
	initialContent := []byte("Original document v1")
	_, err = store.SaveDocument("spec.pdf", bytes.NewReader(initialContent))
	if err != nil {
		t.Fatalf("Save document: %v", err)
	}

	// Create outbox message attaching spec.pdf
	payload := map[string]string{"title": "Proposal", "version": "1.0"}
	msg, err := store.CreateOutboxMessage(payload, []string{"spec.pdf"})
	if err != nil {
		t.Fatalf("Create outbox message: %v", err)
	}

	if len(msg.Attachments) != 1 {
		t.Fatalf("Expected 1 attachment, got %d", len(msg.Attachments))
	}
	attPath, err := store.GetOutboxAttachmentPath(msg.ID, "spec.pdf")
	if err != nil {
		t.Fatalf("Get attachment path: %v", err)
	}

	// Now MODIFY the original document in docs/
	modifiedContent := []byte("Tampered / Modified document v2 !!!")
	_, err = store.SaveDocument("spec.pdf", bytes.NewReader(modifiedContent))
	if err != nil {
		t.Fatalf("Overwrite document: %v", err)
	}

	// Verify that the outbox message attachment remains IMMUTABLE! (Rule 1)
	snapshotData, err := os.ReadFile(attPath)
	if err != nil {
		t.Fatalf("Read snapshot file: %v", err)
	}

	if !bytes.Equal(snapshotData, initialContent) {
		t.Errorf("Immutability violation! Outbox snapshot was modified when original file changed")
	}

	// Delete the original document completely from docs/
	_ = store.DeleteDocument("spec.pdf")

	// Snapshot must still exist
	snapshotDataAfterDelete, err := os.ReadFile(attPath)
	if err != nil || !bytes.Equal(snapshotDataAfterDelete, initialContent) {
		t.Errorf("Immutability violation! Outbox snapshot lost when original doc deleted")
	}
}

func TestStorage_ServerRestartPersistence(t *testing.T) {
	tmpDir := t.TempDir()

	// Instance 1
	store1, err := umaiserver.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage 1: %v", err)
	}

	_, _ = store1.SaveDocument("doc.txt", bytes.NewReader([]byte("persisted")))
	msg, err := store1.CreateOutboxMessage(map[string]string{"foo": "bar"}, []string{"doc.txt"})
	if err != nil {
		t.Fatalf("Create outbox message: %v", err)
	}

	// Accept an incoming message
	_, err = store1.AcceptMessage("msg-incoming-42", "payload", []umaiserver.AttachmentReader{
		{Name: "data.bin", Reader: bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04})},
	})
	if err != nil {
		t.Fatalf("Accept message: %v", err)
	}

	// "Restart": Initialize new storage instance pointing to the same dataDir
	store2, err := umaiserver.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage 2 (restart): %v", err)
	}

	// Check outbox message is still present
	outboxMsgs, err := store2.ListOutbox()
	if err != nil || len(outboxMsgs) != 1 || outboxMsgs[0].ID != msg.ID {
		t.Errorf("Pending outbox message not recovered after restart")
	}

	// Check accepted message ID is still present
	if !store2.IsAccepted("msg-incoming-42") {
		t.Errorf("Accepted message ID msg-incoming-42 not recovered after restart")
	}

	// Check inbox message and attachments exist
	inboxMsg, err := store2.GetInboxMessage("msg-incoming-42")
	if err != nil {
		t.Fatalf("Get inbox message after restart: %v", err)
	}
	if len(inboxMsg.Attachments) != 1 {
		t.Fatalf("Inbox attachments lost after restart")
	}
}

func TestStorage_CrashRecoveryAndFailClosedAck(t *testing.T) {
	tmpDir := t.TempDir()
	store1, err := umaiserver.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage 1: %v", err)
	}

	// Accept a message normally
	_, err = store1.AcceptMessage("msg-crash-99", map[string]string{"k": "v"}, nil)
	if err != nil {
		t.Fatalf("AcceptMessage: %v", err)
	}

	// Simulate a crash right after inbox/{id} was renamed into place before accepted.json was written,
	// plus an orphaned staging directory left behind in .staging/
	_ = os.Remove(filepath.Join(tmpDir, "accepted.json"))
	orphanTmp := filepath.Join(tmpDir, ".staging", "inbox-msg-orphan-12345")
	_ = os.MkdirAll(orphanTmp, 0700)

	// Restart storage: NewStorage must purge .staging/ and reconcile inbox/msg-crash-99 into acceptedIDs
	store2, err := umaiserver.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage 2: %v", err)
	}
	if _, err := os.Stat(orphanTmp); !os.IsNotExist(err) {
		t.Errorf("Expected orphaned .staging directory to be purged on startup")
	}
	if !store2.IsAccepted("msg-crash-99") {
		t.Errorf("Expected msg-crash-99 to be reconciled from inbox/ into acceptedIDs on startup")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "accepted.json")); err != nil {
		t.Errorf("Expected accepted.json to be persisted after startup reconciliation: %v", err)
	}

	// Verify fail-closed AcknowledgeMessagesVerified when outbox message.json is corrupt or unsigned
	pubA, privA := umaiserver.DeriveDemoKeyPair("app-a")
	pubB, _ := umaiserver.DeriveDemoKeyPair("app-b")
	store2.SetKeys("app-a", pubA, privA, pubB)

	outMsg, err := store2.CreateOutboxMessage(map[string]string{"hello": "world"}, nil)
	if err != nil {
		t.Fatalf("CreateOutboxMessage: %v", err)
	}

	// Corrupt outbox/{id}/message.json by stripping its signature on disk
	msgFile := filepath.Join(tmpDir, "outbox", outMsg.ID, "message.json")
	_ = os.WriteFile(msgFile, []byte(`{"id":"`+outMsg.ID+`","signature":""}`), 0600)

	if err := store2.AcknowledgeMessagesVerified([]string{outMsg.ID}, map[string]string{outMsg.ID: "deadbeef"}); err == nil {
		t.Errorf("Expected fail-closed error when outbox message on disk has empty signature")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "outbox", outMsg.ID)); err != nil {
		t.Errorf("Outbox directory must NOT be deleted when AcknowledgeMessagesVerified fails closed")
	}

	// Verify D2: legitimate message IDs and document filenames containing ".tmp-" or starting with "." (e.g. ".tmp-1") survive restart and appear in listings
	if _, err := store2.SaveDocument("contract.tmp-final.txt", bytes.NewReader([]byte("important contract"))); err != nil {
		t.Fatalf("SaveDocument(contract.tmp-final.txt): %v", err)
	}
	if _, err := store2.AcceptMessage(".tmp-1", map[string]string{"ok": "true"}, nil); err != nil {
		t.Fatalf("AcceptMessage(.tmp-1): %v", err)
	}
	if _, err := store2.AcceptMessage("legit.tmp-message", map[string]string{"ok": "true"}, nil); err != nil {
		t.Fatalf("AcceptMessage(legit.tmp-message): %v", err)
	}

	// Verify D3: duplicate attachment filenames in a message are rejected via O_EXCL / exact deduplication
	_, err = store2.AcceptMessage("msg-dup-collision", map[string]string{}, []umaiserver.AttachmentReader{
		{Name: "Invoice.txt", Reader: bytes.NewReader([]byte("first"))},
		{Name: "Invoice.txt", Reader: bytes.NewReader([]byte("second"))},
	})
	if err == nil {
		t.Errorf("Expected colliding attachment filenames to be rejected (D3)")
	}

	// Restart into store3 and confirm .tmp-1, legit.tmp-message, and contract.tmp-final.txt are still intact and listed!
	store3, err := umaiserver.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage 3: %v", err)
	}
	if _, err := store3.GetDocumentPath("contract.tmp-final.txt"); err != nil {
		t.Errorf("Expected contract.tmp-final.txt to survive restart (D2), got: %v", err)
	}
	if _, err := store3.GetInboxMessage(".tmp-1"); err != nil {
		t.Errorf("Expected .tmp-1 in inbox to survive restart (D2), got: %v", err)
	}
	if _, err := store3.GetInboxMessage("legit.tmp-message"); err != nil {
		t.Errorf("Expected legit.tmp-message in inbox to survive restart (D2), got: %v", err)
	}
	inboxMsgs, err := store3.ListInbox()
	if err != nil {
		t.Fatalf("ListInbox: %v", err)
	}
	foundDotTmp := false
	for _, m := range inboxMsgs {
		if m.ID == ".tmp-1" {
			foundDotTmp = true
		}
	}
	if !foundDotTmp {
		t.Errorf("Expected .tmp-1 to be returned by ListInbox() (D2)")
	}
}
