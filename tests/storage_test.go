package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/umai-protocol/umai/internal/demoapp"
	"github.com/umai-protocol/umai/pkg/umaispool"
)

func TestStorage_DocumentLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	docs, err := demoapp.NewDocStore(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Failed to init DocStore: %v", err)
	}

	content := []byte("Hello, UMAI world! Binary document test.")
	docInfo, err := docs.SaveDocument("test_doc.txt", bytes.NewReader(content))
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
	path, err := docs.GetDocumentPath("test_doc.txt")
	if err != nil {
		t.Fatalf("Failed to get doc path: %v", err)
	}
	readBytes, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(readBytes, content) {
		t.Fatalf("File content read from path differs from saved content")
	}

	// Traversal attack protection
	_, err = docs.SaveDocument("../../../etc/passwd", bytes.NewReader(content))
	if err == nil {
		p, err := docs.GetDocumentPath("passwd")
		if err == nil && !filepath.HasPrefix(p, filepath.Join(tmpDir, "docs")) {
			t.Errorf("Path escaped docsDir: %s", p)
		}
	}

	_, err = docs.GetDocumentPath("../../outside.txt")
	if err == nil {
		t.Errorf("Expected error on directory traversal query")
	}

	// Delete
	if err := docs.DeleteDocument("test_doc.txt"); err != nil {
		t.Fatalf("Failed to delete document: %v", err)
	}

	_, err = docs.GetDocumentPath("test_doc.txt")
	if err == nil {
		t.Errorf("Expected error retrieving deleted document")
	}
}

func TestStorage_ImmutabilityAndSnapshots(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage: %v", err)
	}
	docs, err := demoapp.NewDocStore(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init DocStore: %v", err)
	}

	// Create original document in docs/
	initialContent := []byte("Original document v1")
	_, err = docs.SaveDocument("spec.pdf", bytes.NewReader(initialContent))
	if err != nil {
		t.Fatalf("Save document: %v", err)
	}

	// Open spec.pdf and snapshot into immutable outbox message
	docPath, err := docs.GetDocumentPath("spec.pdf")
	if err != nil {
		t.Fatalf("GetDocumentPath: %v", err)
	}
	docFile, err := os.Open(docPath)
	if err != nil {
		t.Fatalf("Open doc: %v", err)
	}
	payload := map[string]string{"title": "Proposal", "version": "1.0"}
	msg, err := store.CreateOutboxMessage(payload, []umaispool.AttachmentReader{
		{Name: "spec.pdf", Reader: docFile},
	})
	_ = docFile.Close()
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
	_, err = docs.SaveDocument("spec.pdf", bytes.NewReader(modifiedContent))
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
	_ = docs.DeleteDocument("spec.pdf")

	// Snapshot must still exist
	snapshotDataAfterDelete, err := os.ReadFile(attPath)
	if err != nil || !bytes.Equal(snapshotDataAfterDelete, initialContent) {
		t.Errorf("Immutability violation! Outbox snapshot lost when original doc deleted")
	}
}

func TestStorage_ServerRestartPersistence(t *testing.T) {
	tmpDir := t.TempDir()

	// Instance 1
	store1, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage 1: %v", err)
	}

	msg, err := store1.CreateOutboxMessage(map[string]string{"foo": "bar"}, []umaispool.AttachmentReader{
		{Name: "doc.txt", Reader: bytes.NewReader([]byte("persisted"))},
	})
	if err != nil {
		t.Fatalf("Create outbox message: %v", err)
	}

	// Accept an incoming message
	_, err = store1.AcceptMessage("msg-incoming-42", "payload", []umaispool.AttachmentReader{
		{Name: "data.bin", Reader: bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04})},
	})
	if err != nil {
		t.Fatalf("Accept message: %v", err)
	}

	// "Restart": Initialize new storage instance pointing to the same dataDir
	store2, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
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
	store1, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
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
	store2, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
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
	_, privA := demoapp.DeriveDemoKeyPair("app-a")
	pubB, _ := demoapp.DeriveDemoKeyPair("app-b")
	if err := store2.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-a",
		PeerIdentity:  "app-b",
		PrivateKey:    privA,
		PeerPublicKey: pubB,
	}); err != nil {
		t.Fatalf("SetSigningConfig: %v", err)
	}

	outMsg, err := store2.CreateOutboxMessage(map[string]string{"hello": "world"}, nil)
	if err != nil {
		t.Fatalf("CreateOutboxMessage: %v", err)
	}

	// Corrupt outbox/{dirKey}/message.json by stripping its signature on disk
	outDirKey, err := umaispool.StorageDirKey(outMsg.ID)
	if err != nil {
		t.Fatalf("StorageDirKey: %v", err)
	}
	msgFile := filepath.Join(tmpDir, "outbox", outDirKey, "message.json")
	_ = os.WriteFile(msgFile, []byte(`{"id":"`+outMsg.ID+`","signature":""}`), 0600)

	if err := store2.AcknowledgeMessagesVerified([]string{outMsg.ID}, map[string]string{outMsg.ID: "deadbeef"}); err == nil {
		t.Errorf("Expected fail-closed error when outbox message on disk has empty signature")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "outbox", outDirKey)); err != nil {
		t.Errorf("Outbox directory must NOT be deleted when AcknowledgeMessagesVerified fails closed")
	}

	// Verify D2: legitimate message IDs and document filenames containing ".tmp-" or starting with "." (e.g. ".tmp-1") survive restart and appear in listings
	docs2, err := demoapp.NewDocStore(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewDocStore: %v", err)
	}
	if _, err := docs2.SaveDocument("contract.tmp-final.txt", bytes.NewReader([]byte("important contract"))); err != nil {
		t.Fatalf("SaveDocument(contract.tmp-final.txt): %v", err)
	}
	if _, err := store2.AcceptMessage(".tmp-1", map[string]string{"ok": "true"}, nil); err != nil {
		t.Fatalf("AcceptMessage(.tmp-1): %v", err)
	}
	if _, err := store2.AcceptMessage("legit.tmp-message", map[string]string{"ok": "true"}, nil); err != nil {
		t.Fatalf("AcceptMessage(legit.tmp-message): %v", err)
	}

	// Verify D3: duplicate attachment filenames in a message are rejected via O_EXCL / exact deduplication
	_, err = store2.AcceptMessage("msg-dup-collision", map[string]string{}, []umaispool.AttachmentReader{
		{Name: "Invoice.txt", Reader: bytes.NewReader([]byte("first"))},
		{Name: "Invoice.txt", Reader: bytes.NewReader([]byte("second"))},
	})
	if err == nil {
		t.Errorf("Expected colliding attachment filenames to be rejected (D3)")
	}

	// Restart into store3 and confirm .tmp-1, legit.tmp-message, and contract.tmp-final.txt are still intact and listed!
	store3, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init storage 3: %v", err)
	}
	docs3, err := demoapp.NewDocStore(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Init docs 3: %v", err)
	}
	if _, err := docs3.GetDocumentPath("contract.tmp-final.txt"); err != nil {
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

func TestStorage_IndexWriteFailure_CommitRecovery_And_HotFolderDeletion(t *testing.T) {
	tmpDir := t.TempDir()
	pubA, privA := demoapp.DeriveDemoKeyPair("app-a")
	_, privB := demoapp.DeriveDemoKeyPair("app-b")

	store, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if err := store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	}); err != nil {
		t.Fatalf("SetSigningConfig: %v", err)
	}

	msgID := "msg-idx-atomic-1"
	payload := map[string]string{"doc": "atomic-index"}
	attBytes := []byte("attachment payload")
	attHash := sha256.Sum256(attBytes)
	sigHex, err := umaispool.SignPutMessage(privA, "app-a", "app-b", msgID, payload, []umaispool.AttachmentInfo{
		{Name: "doc.bin", Size: int64(len(attBytes)), SHA256: hex.EncodeToString(attHash[:])},
	})
	if err != nil {
		t.Fatalf("SignPutMessage: %v", err)
	}

	// 1. Force accepted.json atomic rename to fail by obstructing accepted.json with a non-empty directory.
	acceptedPath := filepath.Join(tmpDir, "accepted.json")
	_ = os.Remove(acceptedPath)
	if err := os.MkdirAll(filepath.Join(acceptedPath, "blocker"), 0700); err != nil {
		t.Fatalf("MkdirAll blocker: %v", err)
	}

	_, err = store.AcceptSignedMessage(msgID, payload, []umaispool.AttachmentReader{
		{Name: "doc.bin", Reader: bytes.NewReader(attBytes)},
	}, sigHex)
	if err == nil {
		t.Fatalf("Expected AcceptSignedMessage to fail when accepted.json cannot be written")
	}
	if store.IsAccepted(msgID) {
		t.Fatalf("IsAccepted must be false when accepted.json commit failed")
	}
	// Verify uncommitted message was NEVER exposed in inbox/ to external hot-folder consumers
	inboxEntries, _ := os.ReadDir(filepath.Join(tmpDir, "inbox"))
	if len(inboxEntries) != 0 {
		t.Fatalf("Expected 0 directories in inbox/ after failed accepted.json write, got %d", len(inboxEntries))
	}

	// Remove blocker and restart storage: state must be consistently unaccepted (IsAccepted == false && GetInboxMessage == ErrNotFound)
	_ = os.RemoveAll(acceptedPath)
	storeRestarted, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Restart NewStorage: %v", err)
	}
	_ = storeRestarted.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	})
	if storeRestarted.IsAccepted(msgID) {
		t.Fatalf("After restart following failed commit, IsAccepted(%s) must remain false", msgID)
	}
	if _, err := storeRestarted.GetInboxMessage(msgID); !errors.Is(err, umaispool.ErrNotFound) {
		t.Fatalf("Expected ErrNotFound on GetInboxMessage(%s), got %v", msgID, err)
	}

	// 2. Retry acceptance now that accepted.json is writable -> must succeed and expose inbox/m-<sha256(id)>
	acceptedMsg, err := storeRestarted.AcceptSignedMessage(msgID, payload, []umaispool.AttachmentReader{
		{Name: "doc.bin", Reader: bytes.NewReader(attBytes)},
	}, sigHex)
	if err != nil {
		t.Fatalf("Retry AcceptSignedMessage failed: %v", err)
	}
	if acceptedMsg.AckReceipt == "" {
		t.Fatalf("Expected non-empty signed AckReceipt")
	}

	// 3. Simulate external hot-folder consumer immediately archiving & deleting inbox/m-<sha256(id)>, then server restart
	dirKey, _ := umaispool.StorageDirKey(msgID)
	if err := os.RemoveAll(filepath.Join(tmpDir, "inbox", dirKey)); err != nil {
		t.Fatalf("Failed to remove inbox dir in hot-folder simulation: %v", err)
	}
	storeAfterConsume, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Restart after hot-folder deletion: %v", err)
	}
	_ = storeAfterConsume.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	})
	if !storeAfterConsume.IsAccepted(msgID) {
		t.Fatalf("Expected IsAccepted(%s) == true after hot-folder consumer deleted inbox dir", msgID)
	}
	if gotRec := storeAfterConsume.ListAcceptedReceipts()[msgID]; gotRec != acceptedMsg.AckReceipt {
		t.Fatalf("Expected preserved AckReceipt %q after hot-folder deletion, got %q", acceptedMsg.AckReceipt, gotRec)
	}
	// Duplicate signed PUT with matching signature must return stored receipt, while forged signature must fail
	dupMsg, err := storeAfterConsume.AcceptSignedMessage(msgID, payload, nil, sigHex)
	if err != nil || dupMsg.AckReceipt != acceptedMsg.AckReceipt {
		t.Fatalf("Expected duplicate signed PUT after hot-folder deletion to return stored receipt, got err=%v", err)
	}
	if _, err := storeAfterConsume.AcceptSignedMessage(msgID, payload, nil, "deadbeef"); err == nil {
		t.Fatalf("Expected forged signature on already-archived message ID to be rejected")
	}

	// 4. Simulate crash between accepted.json commit and final rename from .committing/ into inbox/
	crashID := "msg-crash-after-index"
	crashKey, _ := umaispool.StorageDirKey(crashID)
	commPath := filepath.Join(tmpDir, ".committing", crashKey)
	_ = os.MkdirAll(filepath.Join(commPath, "attachments"), 0700)
	crashMsgBytes, _ := json.Marshal(umaispool.Message{
		ID:         crashID,
		Payload:    map[string]string{"recovered": "yes"},
		AckReceipt: "rec-crash-1",
	})
	_ = os.WriteFile(filepath.Join(commPath, "message.json"), crashMsgBytes, 0600)
	consolidatedBytes, _ := json.Marshal(map[string]string{
		msgID:   acceptedMsg.AckReceipt,
		crashID: "rec-crash-1",
	})
	_ = os.WriteFile(filepath.Join(tmpDir, "accepted.json"), consolidatedBytes, 0600)

	storeRecovered, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Restart for .committing recovery: %v", err)
	}
	if !storeRecovered.IsAccepted(crashID) {
		t.Fatalf("Expected %s to remain accepted", crashID)
	}
	if _, err := storeRecovered.GetInboxMessage(crashID); err != nil {
		t.Fatalf("Expected %s in .committing/ to be promoted to inbox/ on startup, got: %v", crashID, err)
	}
	if got := storeRecovered.ListAcceptedReceipts()[crashID]; got != "rec-crash-1" {
		t.Fatalf("Expected preserved receipt rec-crash-1 after .committing recovery, got %q", got)
	}
}

func TestStorage_FailedDataDirSync_KeepsMessageUnconfirmedAndOutOfInbox(t *testing.T) {
	tmpDir := t.TempDir()
	absTmpDir, err := filepath.Abs(tmpDir)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	pubA, privA := demoapp.DeriveDemoKeyPair("app-a")
	pubB, privB := demoapp.DeriveDemoKeyPair("app-b")

	store, err := umaispool.NewStorage(absTmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	_ = store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	})

	msgID := "msg-sync-fault-1"
	payload := map[string]string{"case": "durability-flush"}
	attBytes := []byte("important binary content")
	attHash := sha256.Sum256(attBytes)
	sigHex, err := umaispool.SignPutMessage(privA, "app-a", "app-b", msgID, payload, []umaispool.AttachmentInfo{
		{Name: "evidence.bin", Size: int64(len(attBytes)), SHA256: hex.EncodeToString(attHash[:])},
	})
	if err != nil {
		t.Fatalf("SignPutMessage: %v", err)
	}

	// Inject a synchronization failure specifically on dataDir (right after accepted.json rename succeeds).
	store.SetSyncDirForTesting(func(dirPath string) error {
		if dirPath == absTmpDir {
			return errors.New("injected dataDir fsync error")
		}
		return nil
	})

	// 1. Initial acceptance must return the injected synchronization error.
	_, err = store.AcceptSignedMessage(msgID, payload, []umaispool.AttachmentReader{
		{Name: "evidence.bin", Reader: bytes.NewReader(attBytes)},
	}, sigHex)
	if err == nil {
		t.Fatalf("Expected AcceptSignedMessage to fail when dataDir synchronization fails")
	}

	// 2. Consumer-visible inbox/ MUST remain empty while the staged recovery copy stays in .committing/.
	inboxEntries, err := os.ReadDir(filepath.Join(absTmpDir, "inbox"))
	if err != nil || len(inboxEntries) != 0 {
		t.Fatalf("Expected 0 visible inbox/ directories after failed dataDir sync, got %d (err=%v)", len(inboxEntries), err)
	}
	dirKey, _ := umaispool.StorageDirKey(msgID)
	if _, err := os.Stat(filepath.Join(absTmpDir, ".committing", dirKey, "message.json")); err != nil {
		t.Fatalf("Expected recovery copy to remain preserved in .committing/%s, got: %v", dirKey, err)
	}

	// 3. Acceptance MUST NOT be reported as confirmed while the durability failure remains active.
	if store.IsAccepted(msgID) {
		t.Fatalf("IsAccepted(%s) must remain false while dataDir sync is unresolved", msgID)
	}
	if _, err := store.GetInboxMessage(msgID); !errors.Is(err, umaispool.ErrNotFound) {
		t.Fatalf("GetInboxMessage(%s) must return ErrNotFound while unconfirmed, got: %v", msgID, err)
	}
	if _, err := store.GetAcceptance([]string{msgID}); err == nil {
		t.Fatalf("GetAcceptance([%s]) must fail (not return accepted:true) while dataDir sync failure remains active", msgID)
	}

	// 4. Duplicate acceptance MUST also fail while the synchronization failure remains active (and reject forged signatures).
	if _, err := store.AcceptSignedMessage(msgID, payload, []umaispool.AttachmentReader{
		{Name: "evidence.bin", Reader: bytes.NewReader(attBytes)},
	}, sigHex); err == nil {
		t.Fatalf("Duplicate AcceptSignedMessage must fail while dataDir sync failure remains active")
	}
	if _, err := store.AcceptSignedMessage(msgID, payload, nil, "deadbeef"); !errors.Is(err, umaispool.ErrInvalidSignature) {
		t.Fatalf("Expected ErrInvalidSignature on forged duplicate PUT during pending commit, got: %v", err)
	}

	// 5. Clear the injected synchronization fault: GetAcceptance (or retry AcceptSignedMessage) must finalize cleanly,
	//    exposing inbox/m-<sha256(id)> and returning confirmed acceptance with a valid signed receipt.
	store.SetSyncDirForTesting(nil)
	accMap, err := store.GetAcceptance([]string{msgID})
	if err != nil {
		t.Fatalf("Expected GetAcceptance to finalize pending commit once syncDir succeeds, got: %v", err)
	}
	status := accMap[msgID]
	if !status.Accepted || status.AckReceipt == "" {
		t.Fatalf("Expected confirmed acceptance with non-empty receipt after finalization, got: %+v", status)
	}
	if err := umaispool.VerifyAckReceipt(pubB, "app-b", msgID, sigHex, status.AckReceipt); err != nil {
		t.Fatalf("Expected valid Ed25519 AckReceipt after finalization: %v", err)
	}
	if !store.IsAccepted(msgID) {
		t.Fatalf("Expected IsAccepted(%s) == true after finalization", msgID)
	}
	if _, err := store.GetInboxMessage(msgID); err != nil {
		t.Fatalf("Expected message to be visible via GetInboxMessage after finalization, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(absTmpDir, ".committing", dirKey)); !os.IsNotExist(err) {
		t.Fatalf("Expected .committing/%s to be moved into inbox/ after finalization", dirKey)
	}
}

func TestStorage_CaseInsensitiveIDCollisions_And_WindowsProblematicIDs(t *testing.T) {
	tmpDir := t.TempDir()
	pubA, privA := demoapp.DeriveDemoKeyPair("app-a")
	_, privB := demoapp.DeriveDemoKeyPair("app-b")

	store, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	_ = store.SetSigningConfig(umaispool.SigningConfig{
		LocalIdentity: "app-b",
		PeerIdentity:  "app-a",
		PrivateKey:    privB,
		PeerPublicKey: pubA,
	})

	cases := []struct {
		id      string
		content []byte
	}{
		{id: "CaseID", content: []byte("UPPER-CASE-MESSAGE")},
		{id: "caseid", content: []byte("lower-case-message")},
		{id: "con", content: []byte("windows-reserved-con")},
		{id: "nul", content: []byte("windows-reserved-nul")},
		{id: "trailing.", content: []byte("windows-trailing-dot")},
	}

	for _, tc := range cases {
		h := sha256.Sum256(tc.content)
		payload := map[string]string{"exact_id": tc.id}
		sig, err := umaispool.SignPutMessage(privA, "app-a", "app-b", tc.id, payload, []umaispool.AttachmentInfo{
			{Name: "body.bin", Size: int64(len(tc.content)), SHA256: hex.EncodeToString(h[:])},
		})
		if err != nil {
			t.Fatalf("SignPutMessage(%s): %v", tc.id, err)
		}
		if _, err := store.AcceptSignedMessage(tc.id, payload, []umaispool.AttachmentReader{
			{Name: "body.bin", Reader: bytes.NewReader(tc.content)},
		}, sig); err != nil {
			t.Fatalf("AcceptSignedMessage(%s) failed: %v", tc.id, err)
		}
	}

	// Restart storage and verify every case-colliding and OS-sensitive ID preserved its own distinct message & bytes
	restarted, err := umaispool.NewStorage(tmpDir, 10*1024*1024)
	if err != nil {
		t.Fatalf("Restart NewStorage: %v", err)
	}
	for _, tc := range cases {
		msg, err := restarted.GetInboxMessage(tc.id)
		if err != nil {
			t.Fatalf("GetInboxMessage(%q) failed: %v", tc.id, err)
		}
		if msg.ID != tc.id {
			t.Fatalf("Expected exact ID %q, got %q", tc.id, msg.ID)
		}
		attPath, err := restarted.GetInboxAttachmentPath(tc.id, "body.bin")
		if err != nil {
			t.Fatalf("GetInboxAttachmentPath(%q) failed: %v", tc.id, err)
		}
		gotBytes, err := os.ReadFile(attPath)
		if err != nil || !bytes.Equal(gotBytes, tc.content) {
			t.Fatalf("Message %q attachment overwritten or corrupted: got %q, want %q", tc.id, string(gotBytes), string(tc.content))
		}
	}

	// Verify batch GetAcceptance returns explicit status + ackReceipt for accepted IDs and accepted: false for unaccepted IDs
	batchRes, err := restarted.GetAcceptance([]string{"CaseID", "caseid", "unaccepted-id-1"})
	if err != nil {
		t.Fatalf("GetAcceptance failed: %v", err)
	}
	if !batchRes["CaseID"].Accepted || batchRes["CaseID"].AckReceipt == "" {
		t.Errorf("Expected CaseID to be accepted with non-empty AckReceipt, got %+v", batchRes["CaseID"])
	}
	if !batchRes["caseid"].Accepted || batchRes["caseid"].AckReceipt == "" {
		t.Errorf("Expected caseid to be accepted with non-empty AckReceipt, got %+v", batchRes["caseid"])
	}
	if batchRes["CaseID"].AckReceipt == batchRes["caseid"].AckReceipt {
		t.Errorf("Distinct messages CaseID and caseid must have distinct AckReceipts")
	}
	if uStatus, exists := batchRes["unaccepted-id-1"]; !exists || uStatus.Accepted || uStatus.AckReceipt != "" {
		t.Errorf("Expected explicit {Accepted: false} for unaccepted-id-1, got exists=%v status=%+v", exists, uStatus)
	}

	// Verify invalid IDs and >MaxBatchIDs batches are rejected
	if _, err := restarted.GetAcceptance([]string{"../bad"}); err == nil {
		t.Errorf("Expected GetAcceptance to reject invalid message ID")
	}
	tooMany := make([]string, umaispool.MaxBatchIDs+1)
	for i := range tooMany {
		tooMany[i] = "msg-ok"
	}
	if _, err := restarted.GetAcceptance(tooMany); err == nil {
		t.Errorf("Expected GetAcceptance to reject batch exceeding MaxBatchIDs")
	}
}
