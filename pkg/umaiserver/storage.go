package umaiserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	MaxAttachmentsPerMessage = 50
	OutboxLeaseDuration      = 15 * time.Second
)

var (
	ErrNotFound            = errors.New("not found")
	ErrInvalidID           = errors.New("invalid identifier")
	ErrAlreadyAccepted     = errors.New("message already accepted")
	ErrTraversal           = errors.New("invalid file path / directory traversal detected")
	ErrFileTooLarge        = errors.New("file exceeds maximum allowed size")
	ErrDuplicateAttachment = errors.New("duplicate attachment filename in message")
	ErrTooManyAttachments  = errors.New("too many attachments in message")
)

// DocumentInfo describes a document stored in the local documents directory.
type DocumentInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	SHA256  string    `json:"sha256,omitempty"`
}

// AttachmentInfo describes a binary attachment belonging to a message.
type AttachmentInfo struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Message represents an immutable UMAI message.
type Message struct {
	ID          string           `json:"id"`
	CreatedAt   time.Time        `json:"created_at"`
	Payload     any              `json:"payload"`
	Attachments []AttachmentInfo `json:"attachments"`
	Signature   string           `json:"signature,omitempty"`
	AckReceipt  string           `json:"ack_receipt,omitempty"`
}

// Storage manages local documents, outbox snapshots, inbox messages and accepted IDs.
type Storage struct {
	mu            sync.RWMutex
	dataDir       string
	docsDir       string
	outboxDir     string
	inboxDir      string
	acceptedFile  string
	maxUploadSize int64
	acceptedIDs   map[string]bool
	inFlightUntil map[string]time.Time
	role          string
	peerRole      string
	ownPubKey     ed25519.PublicKey
	ownPrivKey    ed25519.PrivateKey
	peerPubKey    ed25519.PublicKey
}

// NewStorage initializes storage directories and loads accepted message IDs.
func NewStorage(dataDir string, maxUploadSize int64) (*Storage, error) {
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolving data directory: %w", err)
	}

	docsDir := filepath.Join(absDataDir, "docs")
	outboxDir := filepath.Join(absDataDir, "outbox")
	inboxDir := filepath.Join(absDataDir, "inbox")
	acceptedFile := filepath.Join(absDataDir, "accepted.json")

	for _, dir := range []string{absDataDir, docsDir, outboxDir, inboxDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	s := &Storage{
		dataDir:       absDataDir,
		docsDir:       docsDir,
		outboxDir:     outboxDir,
		inboxDir:      inboxDir,
		acceptedFile:  acceptedFile,
		maxUploadSize: maxUploadSize,
		acceptedIDs:   make(map[string]bool),
		inFlightUntil: make(map[string]time.Time),
	}

	if err := s.loadAcceptedIDs(); err != nil {
		return nil, fmt.Errorf("loading accepted IDs: %w", err)
	}

	return s, nil
}

// SetKeys configures the server role, Ed25519 signing key pair, and the expected peer public key.
func (s *Storage) SetKeys(role string, ownPub ed25519.PublicKey, ownPriv ed25519.PrivateKey, peerPub ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.role = role
	if role == "app-b" {
		s.peerRole = "app-a"
	} else {
		s.peerRole = "app-b"
	}
	s.ownPubKey = ownPub
	s.ownPrivKey = ownPriv
	s.peerPubKey = peerPub
}

// PublicKeyHex returns this server's Ed25519 public key in hex.
func (s *Storage) PublicKeyHex() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return hex.EncodeToString(s.ownPubKey)
}

// PeerPublicKeyHex returns the configured peer Ed25519 public key in hex.
func (s *Storage) PeerPublicKeyHex() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return hex.EncodeToString(s.peerPubKey)
}

// sanitizeFilename strips directory elements and keeps only the base filename.
func sanitizeFilename(name string) (string, error) {
	base := filepath.Base(filepath.Clean(name))
	if base == "." || base == "/" || base == "\\" || base == "" || strings.Contains(base, "..") {
		return "", ErrTraversal
	}
	// Strip null bytes and control chars
	clean := strings.Map(func(r rune) rune {
		if r == 0 || r < 32 {
			return -1
		}
		return r
	}, base)
	if clean == "" {
		return "", ErrTraversal
	}
	return clean, nil
}

// sanitizeID ensures message IDs are alphanumeric plus hyphens/underscores.
func sanitizeID(id string) (string, error) {
	clean := strings.TrimSpace(id)
	if clean == "" || len(clean) > 128 {
		return "", ErrInvalidID
	}
	for _, r := range clean {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
			return "", ErrInvalidID
		}
	}
	if strings.Contains(clean, "..") || clean == "." {
		return "", ErrInvalidID
	}
	return clean, nil
}

// GenerateMessageID generates a cryptographically random, globally unique message ID.
func GenerateMessageID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("msg-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b))
}

// -----------------------------------------------------------------------------
// Document Management
// -----------------------------------------------------------------------------

// ListDocuments lists all available documents in docsDir.
func (s *Storage) ListDocuments() ([]DocumentInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.docsDir)
	if err != nil {
		return nil, err
	}

	var docs []DocumentInfo
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		docs = append(docs, DocumentInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	return docs, nil
}

// SaveDocument saves an uploaded file to docsDir.
func (s *Storage) SaveDocument(filename string, r io.Reader) (*DocumentInfo, error) {
	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	targetPath := filepath.Join(s.docsDir, cleanName)
	tmpPath := targetPath + fmt.Sprintf(".tmp-%d", time.Now().UnixNano())

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	limitReader := io.LimitReader(r, s.maxUploadSize+1)
	writer := io.MultiWriter(f, hasher)

	n, err := io.Copy(writer, limitReader)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}

	if n > s.maxUploadSize {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, ErrFileTooLarge
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	_ = f.Close()

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	hashStr := hex.EncodeToString(hasher.Sum(nil))
	return &DocumentInfo{
		Name:    cleanName,
		Size:    n,
		ModTime: time.Now(),
		SHA256:  hashStr,
	}, nil
}

// GetDocumentPath returns the safe absolute path for downloading a document.
func (s *Storage) GetDocumentPath(filename string) (string, error) {
	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	targetPath := filepath.Join(s.docsDir, cleanName)
	if fi, err := os.Stat(targetPath); err != nil || fi.IsDir() {
		return "", ErrNotFound
	}
	return targetPath, nil
}

// DeleteDocument removes a file from docsDir.
func (s *Storage) DeleteDocument(filename string) error {
	cleanName, err := sanitizeFilename(filename)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	targetPath := filepath.Join(s.docsDir, cleanName)
	if err := os.Remove(targetPath); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// -----------------------------------------------------------------------------
// Outbox Management (Rule 1: Immutability & Snapshots)
// -----------------------------------------------------------------------------

// CreateOutboxMessage creates an immutable message snapshot in outboxDir.
func (s *Storage) CreateOutboxMessage(payload any, docNames []string) (*Message, error) {
	if len(docNames) > MaxAttachmentsPerMessage {
		return nil, ErrTooManyAttachments
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	msgID := GenerateMessageID()
	msgDir := filepath.Join(s.outboxDir, msgID)
	attachmentsDir := filepath.Join(msgDir, "attachments")

	if err := os.MkdirAll(attachmentsDir, 0755); err != nil {
		return nil, err
	}

	var attachments []AttachmentInfo
	seenNames := make(map[string]bool)

	// Copy selected documents into snapshot directory
	for _, rawName := range docNames {
		cleanName, err := sanitizeFilename(rawName)
		if err != nil {
			_ = os.RemoveAll(msgDir)
			return nil, err
		}
		if seenNames[cleanName] {
			_ = os.RemoveAll(msgDir)
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
		}
		seenNames[cleanName] = true

		srcPath := filepath.Join(s.docsDir, cleanName)
		srcFile, err := os.Open(srcPath)
		if err != nil {
			_ = os.RemoveAll(msgDir)
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("attachment %s does not exist: %w", cleanName, ErrNotFound)
			}
			return nil, err
		}

		dstPath := filepath.Join(attachmentsDir, cleanName)
		dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			_ = srcFile.Close()
			_ = os.RemoveAll(msgDir)
			return nil, err
		}

		hasher := sha256.New()
		writer := io.MultiWriter(dstFile, hasher)
		n, err := io.Copy(writer, srcFile)
		_ = srcFile.Close()
		if err != nil {
			_ = dstFile.Close()
			_ = os.RemoveAll(msgDir)
			return nil, err
		}
		if err := dstFile.Sync(); err != nil {
			_ = dstFile.Close()
			_ = os.RemoveAll(msgDir)
			return nil, err
		}
		_ = dstFile.Close()

		attachments = append(attachments, AttachmentInfo{
			Name:   cleanName,
			Size:   n,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
	}

	sigHex, err := SignPutMessage(s.ownPrivKey, s.role, msgID, payload, attachments)
	if err != nil {
		_ = os.RemoveAll(msgDir)
		return nil, err
	}

	msg := &Message{
		ID:          msgID,
		CreatedAt:   time.Now().UTC(),
		Payload:     payload,
		Attachments: attachments,
		Signature:   sigHex,
	}

	if err := s.writeAtomicJSON(filepath.Join(msgDir, "message.json"), msg); err != nil {
		_ = os.RemoveAll(msgDir)
		return nil, err
	}

	return msg, nil
}

// ListOutbox returns all active messages in outbox, prioritizing unclaimed messages ahead of
// messages that have an active soft in-flight lease.
func (s *Storage) ListOutbox() ([]*Message, error) {
	return s.ListOutboxForSession("")
}

// ListOutboxForSession returns all active messages in outbox, prioritizing unclaimed messages first
// and deterministically rotating the unclaimed list based on sessionKey so multiple concurrent
// browser sessions naturally pick different messages first without UI flicker.
func (s *Storage) ListOutboxForSession(sessionKey string) ([]*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.outboxDir)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var unclaimed []*Message
	var inFlight []*Message

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		msgFile := filepath.Join(s.outboxDir, entry.Name(), "message.json")
		data, err := os.ReadFile(msgFile)
		if err != nil {
			continue
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err == nil {
			if leaseUntil, ok := s.inFlightUntil[msg.ID]; ok && now.Before(leaseUntil) {
				inFlight = append(inFlight, &msg)
			} else {
				unclaimed = append(unclaimed, &msg)
			}
		}
	}

	if sessionKey != "" && len(unclaimed) > 1 {
		h := sha256.Sum256([]byte(sessionKey))
		offset := int(h[0]) % len(unclaimed)
		if offset > 0 {
			rotated := make([]*Message, 0, len(unclaimed))
			rotated = append(rotated, unclaimed[offset:]...)
			rotated = append(rotated, unclaimed[:offset]...)
			unclaimed = rotated
		}
	}

	messages := make([]*Message, 0, len(unclaimed)+len(inFlight))
	messages = append(messages, unclaimed...)
	messages = append(messages, inFlight...)
	return messages, nil
}

// ListOutboxIDs returns only the IDs of messages in the outbox.
func (s *Storage) ListOutboxIDs() ([]string, error) {
	msgs, err := s.ListOutbox()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	return ids, nil
}

// GetOutboxMessage retrieves a specific message from outbox and places a soft in-flight lease
// on it so other concurrent browser sessions prioritize unclaimed messages first.
func (s *Storage) GetOutboxMessage(id string) (*Message, error) {
	cleanID, err := sanitizeID(id)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	msgFile := filepath.Join(s.outboxDir, cleanID, "message.json")
	data, err := os.ReadFile(msgFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	s.inFlightUntil[cleanID] = time.Now().Add(OutboxLeaseDuration)
	return &msg, nil
}

// GetOutboxAttachmentPath returns path to an attachment file in outbox snapshot.
func (s *Storage) GetOutboxAttachmentPath(id, filename string) (string, error) {
	cleanID, err := sanitizeID(id)
	if err != nil {
		return "", err
	}
	cleanFile, err := sanitizeFilename(filename)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := filepath.Join(s.outboxDir, cleanID, "attachments", cleanFile)
	if fi, err := os.Stat(filePath); err != nil || fi.IsDir() {
		return "", ErrNotFound
	}
	return filePath, nil
}

// AcknowledgeMessages removes acknowledged messages from outbox (Rule 6) without cryptographic receipt verification
// (used only by internal unit tests that test storage cleanup directly).
func (s *Storage) AcknowledgeMessages(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rawID := range ids {
		cleanID, err := sanitizeID(rawID)
		if err != nil {
			continue
		}
		msgDir := filepath.Join(s.outboxDir, cleanID)
		delete(s.inFlightUntil, cleanID)
		_ = os.RemoveAll(msgDir)
	}
	return nil
}

// AcknowledgeMessagesVerified removes acknowledged messages from outbox (Rule 6),
// strictly verifying cryptographic ACK receipts against the peer's public key whenever
// a peer public key is configured and the outbox message was signed.
func (s *Storage) AcknowledgeMessagesVerified(ids []string, receipts map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rawID := range ids {
		cleanID, err := sanitizeID(rawID)
		if err != nil {
			continue
		}
		msgDir := filepath.Join(s.outboxDir, cleanID)
		msgFile := filepath.Join(msgDir, "message.json")
		if len(s.peerPubKey) > 0 {
			data, err := os.ReadFile(msgFile)
			if err == nil {
				var outMsg Message
				if err := json.Unmarshal(data, &outMsg); err == nil && outMsg.Signature != "" {
					receiptHex := ""
					if receipts != nil {
						receiptHex = receipts[cleanID]
					}
					if receiptHex == "" {
						return fmt.Errorf("missing ACK receipt for %s: %w", cleanID, ErrInvalidReceipt)
					}
					if err := VerifyAckReceipt(s.peerPubKey, s.peerRole, cleanID, outMsg.Signature, receiptHex); err != nil {
						return fmt.Errorf("ACK receipt verification failed for %s: %w", cleanID, err)
					}
				}
			}
		}
		delete(s.inFlightUntil, cleanID)
		_ = os.RemoveAll(msgDir)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Inbox & Acceptance Management (Rules 3, 4, 5)
// -----------------------------------------------------------------------------

// IsAccepted returns true if the message ID has already been accepted.
func (s *Storage) IsAccepted(id string) bool {
	cleanID, err := sanitizeID(id)
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.acceptedIDs[cleanID]
}

// ListAccepted returns all accepted message IDs.
func (s *Storage) ListAccepted() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ids []string
	for id := range s.acceptedIDs {
		ids = append(ids, id)
	}
	return ids
}

// ListAcceptedReceipts returns a map of accepted message ID -> cryptographic ACK receipt.
func (s *Storage) ListAcceptedReceipts() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	receipts := make(map[string]string, len(s.acceptedIDs))
	for id := range s.acceptedIDs {
		msgFile := filepath.Join(s.inboxDir, id, "message.json")
		if data, err := os.ReadFile(msgFile); err == nil {
			var m Message
			if err := json.Unmarshal(data, &m); err == nil && m.AckReceipt != "" {
				receipts[id] = m.AckReceipt
				continue
			}
		}
		receipts[id] = ""
	}
	return receipts
}

// ListInbox returns all accepted messages stored in inbox.
func (s *Storage) ListInbox() ([]*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.inboxDir)
	if err != nil {
		return nil, err
	}

	var msgs []*Message
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		msgFile := filepath.Join(s.inboxDir, entry.Name(), "message.json")
		data, err := os.ReadFile(msgFile)
		if err != nil {
			continue
		}
		var msg Message
		if err := json.Unmarshal(data, &msg); err == nil {
			msgs = append(msgs, &msg)
		}
	}
	return msgs, nil
}

// GetInboxMessage retrieves an accepted message from inbox.
func (s *Storage) GetInboxMessage(id string) (*Message, error) {
	cleanID, err := sanitizeID(id)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	msgFile := filepath.Join(s.inboxDir, cleanID, "message.json")
	data, err := os.ReadFile(msgFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// GetInboxAttachmentPath returns path to an attachment in inbox.
func (s *Storage) GetInboxAttachmentPath(id, filename string) (string, error) {
	cleanID, err := sanitizeID(id)
	if err != nil {
		return "", err
	}
	cleanFile, err := sanitizeFilename(filename)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := filepath.Join(s.inboxDir, cleanID, "attachments", cleanFile)
	if fi, err := os.Stat(filePath); err != nil || fi.IsDir() {
		return "", ErrNotFound
	}
	return filePath, nil
}

// AttachmentReader encapsulates an attachment stream for acceptance.
type AttachmentReader struct {
	Name   string
	Reader io.Reader
}

// AcceptMessage performs all-or-nothing acceptance of a PUT message (Rule 3 & 4) without signature enforcement
// (used only by internal storage tests that test raw disk staging directly).
func (s *Storage) AcceptMessage(id string, payload any, attachments []AttachmentReader) (*Message, error) {
	return s.acceptMessageInternal(id, payload, attachments, "", false)
}

// AcceptSignedMessage performs all-or-nothing acceptance of a PUT message (Rule 3 & 4),
// strictly verifying the sender's Ed25519 signature against the configured peer public key.
func (s *Storage) AcceptSignedMessage(id string, payload any, attachments []AttachmentReader, sigHex string) (*Message, error) {
	return s.acceptMessageInternal(id, payload, attachments, sigHex, true)
}

func (s *Storage) acceptMessageInternal(id string, payload any, attachments []AttachmentReader, sigHex string, requireSignature bool) (*Message, error) {
	if len(attachments) > MaxAttachmentsPerMessage {
		return nil, ErrTooManyAttachments
	}

	cleanID, err := sanitizeID(id)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// If already accepted, return existing message (including its stored AckReceipt) without re-importing
	if s.acceptedIDs[cleanID] {
		msgFile := filepath.Join(s.inboxDir, cleanID, "message.json")
		if data, err := os.ReadFile(msgFile); err == nil {
			var existing Message
			if err := json.Unmarshal(data, &existing); err == nil {
				return &existing, nil
			}
		}
		return &Message{ID: cleanID, Payload: payload}, nil
	}

	// Atomic staging directory: all-or-nothing
	tmpDir := filepath.Join(s.inboxDir, fmt.Sprintf(".tmp-%s-%d", cleanID, time.Now().UnixNano()))
	tmpAttachmentsDir := filepath.Join(tmpDir, "attachments")
	if err := os.MkdirAll(tmpAttachmentsDir, 0755); err != nil {
		return nil, err
	}

	var attInfos []AttachmentInfo
	seenNames := make(map[string]bool)
	for _, att := range attachments {
		cleanName, err := sanitizeFilename(att.Name)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if seenNames[cleanName] {
			_ = os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
		}
		seenNames[cleanName] = true

		dstPath := filepath.Join(tmpAttachmentsDir, cleanName)
		dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}

		hasher := sha256.New()
		writer := io.MultiWriter(dstFile, hasher)
		limitReader := io.LimitReader(att.Reader, s.maxUploadSize+1)

		n, err := io.Copy(writer, limitReader)
		if err != nil {
			_ = dstFile.Close()
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}

		if n > s.maxUploadSize {
			_ = dstFile.Close()
			_ = os.RemoveAll(tmpDir)
			return nil, ErrFileTooLarge
		}

		if err := dstFile.Sync(); err != nil {
			_ = dstFile.Close()
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		_ = dstFile.Close()

		attInfos = append(attInfos, AttachmentInfo{
			Name:   cleanName,
			Size:   n,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
	}

	// Enforce Ed25519 signature verification when required and peer public key is configured
	if (requireSignature || sigHex != "") && len(s.peerPubKey) > 0 {
		if err := VerifyPutMessage(s.peerPubKey, s.peerRole, cleanID, payload, attInfos, sigHex); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
	}

	ackReceipt := ""
	if len(s.ownPrivKey) > 0 {
		ackReceipt = SignAckReceipt(s.ownPrivKey, s.role, cleanID, sigHex)
	}

	msg := &Message{
		ID:          cleanID,
		CreatedAt:   time.Now().UTC(),
		Payload:     payload,
		Attachments: attInfos,
		Signature:   sigHex,
		AckReceipt:  ackReceipt,
	}

	if err := s.writeAtomicJSON(filepath.Join(tmpDir, "message.json"), msg); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	targetDir := filepath.Join(s.inboxDir, cleanID)
	// If targetDir somehow exists from aborted prior run, remove it
	_ = os.RemoveAll(targetDir)

	if err := os.Rename(tmpDir, targetDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	// Mark accepted and write accepted.json atomically
	s.acceptedIDs[cleanID] = true
	if err := s.persistAcceptedIDsLocked(); err != nil {
		// Rollback if persisting accepted IDs fails
		delete(s.acceptedIDs, cleanID)
		_ = os.RemoveAll(targetDir)
		return nil, fmt.Errorf("persisting accepted ID: %w", err)
	}

	return msg, nil
}

// -----------------------------------------------------------------------------
// Persistence Helpers
// -----------------------------------------------------------------------------

func (s *Storage) loadAcceptedIDs() error {
	data, err := os.ReadFile(s.acceptedFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	for _, id := range list {
		if clean, err := sanitizeID(id); err == nil {
			s.acceptedIDs[clean] = true
		}
	}
	return nil
}

func (s *Storage) persistAcceptedIDsLocked() error {
	var list []string
	for id := range s.acceptedIDs {
		list = append(list, id)
	}
	return s.writeAtomicJSON(s.acceptedFile, list)
}

func (s *Storage) writeAtomicJSON(targetPath string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := targetPath + fmt.Sprintf(".tmp-%d", time.Now().UnixNano())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	_ = f.Close()

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
