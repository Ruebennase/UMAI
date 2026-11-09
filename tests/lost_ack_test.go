package tests

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"os"
	"testing"
)

// TestMandatory_LostACKVerification implements the exact test required by Section 19:
//
// 1. A sends a message to B.
// 2. B successfully accepts and records the message.
// 3. Deliberately suppress B's first ACK.
// 4. A retains the message in its outbox.
// 5. On the next synchronisation, A offers the same message again.
// 6. B recognises the previously accepted message ID.
// 7. B sends ACK again without requesting or receiving another PUT.
// 8. A processes the ACK and removes the message from its outbox.
// 9. Verify that B has accepted the message exactly once.
func TestMandatory_LostACKVerification(t *testing.T) {
	// Initialize App A and App B in memory
	appA := setupApp(t, "app-a", "http://127.0.0.1:8082")
	appB := setupApp(t, "app-b", "http://127.0.0.1:8081")

	// --- Step 1: A prepares a message with attachment ---
	fileContent := []byte("Contract terms: UMAI 0.1 repeated-ACK test verification")
	_, err := appA.Server.Docs().SaveDocument("contract.pdf", bytes.NewReader(fileContent))
	if err != nil {
		t.Fatalf("Step 1 failed: could not save document on A: %v", err)
	}

	payload := map[string]string{"type": "contract", "title": "Agreement v1"}
	msgA, err := appA.Server.CreateOutboxFromDocs(payload, []string{"contract.pdf"})
	if err != nil {
		t.Fatalf("Step 1 failed: could not create outbox message on A: %v", err)
	}

	// Verify A has the message in outbox
	outboxBefore, _ := appA.Server.Storage().ListOutbox()
	if len(outboxBefore) != 1 || outboxBefore[0].ID != msgA.ID {
		t.Fatalf("Step 1 failed: expected 1 message in A's outbox, found %d", len(outboxBefore))
	}

	// --- Step 2: B successfully accepts and records the message ---
	attPath, _ := appA.Server.Storage().GetOutboxAttachmentPath(msgA.ID, "contract.pdf")
	fileData, _ := os.ReadFile(attPath)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("id", msgA.ID)
	pJSON, _ := json.Marshal(msgA.Payload)
	_ = mw.WriteField("payload", string(pJSON))
	_ = mw.WriteField("signature", msgA.Signature)
	_ = mw.WriteField("attachment_meta", `[{"name":"contract.pdf"}]`)
	part, _ := mw.CreateFormFile("attachments", "contract.pdf")
	_, _ = part.Write(fileData)
	_ = mw.Close()

	req, err := authenticatedRequest("POST", "/api/inbox", appB.SessionID, &buf, mw.FormDataContentType())
	if err != nil {
		t.Fatalf("Step 2 failed: create request: %v", err)
	}
	res := appB.Do(req)
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Step 2 failed: B returned status %v", res.Status)
	}

	// Verify B recorded acceptance
	if !appB.Server.Storage().IsAccepted(msgA.ID) {
		t.Fatalf("Step 2 failed: B did not record message ID as accepted")
	}

	// --- Step 3: Deliberately suppress B's first ACK ---
	t.Logf("Step 3: Deliberately suppressing initial ACK from B to A for message %s", msgA.ID)

	// --- Step 4: A retains the message in its outbox ---
	outboxAAfterSuppress, _ := appA.Server.Storage().ListOutbox()
	if len(outboxAAfterSuppress) != 1 || outboxAAfterSuppress[0].ID != msgA.ID {
		t.Fatalf("Step 4 failed: A should still retain message %s in its outbox", msgA.ID)
	}

	// --- Step 5: On the next synchronisation, A offers the same message again ---
	offeredIDs := []string{msgA.ID}
	t.Logf("Step 5: App A reconnects and re-OFFERs IDs: %v", offeredIDs)

	// --- Step 6: B recognises the previously accepted message ID ---
	var toGet []string
	var repeatedAcks []string

	for _, id := range offeredIDs {
		if appB.Server.Storage().IsAccepted(id) {
			repeatedAcks = append(repeatedAcks, id)
		} else {
			toGet = append(toGet, id)
		}
	}

	if len(repeatedAcks) != 1 || repeatedAcks[0] != msgA.ID {
		t.Fatalf("Step 6 failed: B failed to recognize message ID %s as previously accepted", msgA.ID)
	}

	// --- Step 7: B sends ACK again WITHOUT requesting or receiving another PUT ---
	if len(toGet) != 0 {
		t.Fatalf("Step 7 failed: B violated Rule 5 by requesting a previously accepted message via GET: %v", toGet)
	}
	t.Logf("Step 7: B sends repeated ACK for: %v without sending GET or receiving PUT", repeatedAcks)

	// --- Step 8: A processes the ACK (with B's stored receipt) and removes the message from its outbox ---
	storedReceipts := appB.Server.Storage().ListAcceptedReceipts()
	var ackBuf bytes.Buffer
	_ = json.NewEncoder(&ackBuf).Encode(map[string]any{
		"ids":      repeatedAcks,
		"receipts": storedReceipts,
	})

	ackReq, err := authenticatedRequest("POST", "/api/outbox/ack", appA.SessionID, &ackBuf, "application/json")
	if err != nil {
		t.Fatalf("Step 8 failed: create ack request to A: %v", err)
	}
	ackRes := appA.Do(ackReq)
	defer ackRes.Body.Close()

	if ackRes.StatusCode != http.StatusOK {
		t.Fatalf("Step 8 failed: A returned status %v on ack", ackRes.Status)
	}

	// Verify A processed ACK and removed message from its outbox
	outboxAFinal, _ := appA.Server.Storage().ListOutbox()
	if len(outboxAFinal) != 0 {
		t.Fatalf("Step 8 failed: A should have removed message from outbox after ACK, still has %d", len(outboxAFinal))
	}

	// --- Step 9: Verify that B has accepted the message exactly once ---
	inboxBList, err := appB.Server.Storage().ListInbox()
	if err != nil {
		t.Fatalf("Step 9 failed: could not list B inbox: %v", err)
	}

	countInB := 0
	for _, m := range inboxBList {
		if m.ID == msgA.ID {
			countInB++
		}
	}

	if countInB != 1 {
		t.Fatalf("Step 9 failed: message %s was imported %d times on B, expected exactly 1", msgA.ID, countInB)
	}

	t.Logf("SUCCESS: Mandatory Lost-ACK verification passed completely! Message accepted exactly once and outbox cleaned.")
}
