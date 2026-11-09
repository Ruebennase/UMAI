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
	ErrStorageCollision    = errors.New("storage directory collision detected")
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
//
// Authoritative Inbox Commit & Hot-Folder Visibility Model:
//  1. Incoming files and message.json are written and fsynced in `.staging/`.
//  2. The staged directory is atomically renamed to `.committing/m-<sha256(id)>/` (invisible to `inbox/` consumers).
//  3. `accepted.json` (single consolidated map of `id -> ackReceipt`) is atomically updated and fsynced.
//     This rename onto `accepted.json` is the single authoritative acceptance commit point.
//  4. Only AFTER `accepted.json` is durable on disk is `.committing/m-<sha256(id)>/` renamed into `inbox/m-<sha256(id)>/`.
//     Consequently, an external hot-folder consumer polling `inbox/` can safely archive or delete any directory
//     appearing in `inbox/` without risking loss of the durable acceptance record or signed ACK receipt.
type Storage struct {
	mu                 sync.RWMutex
	dataDir            string
	stagingDir         string
	committingDir      string
	docsDir            string
	outboxDir          string
	inboxDir           string
	acceptedFile       string
	legacyReceiptsFile string
	maxUploadSize      int64
	acceptedIDs        map[string]bool
	acceptedReceipts   map[string]string
	inFlightUntil      map[string]time.Time
	role               string
	peerRole           string
	ownPubKey          ed25519.PublicKey
	ownPrivKey         ed25519.PrivateKey
	peerPubKey         ed25519.PublicKey
}

// NewStorage initializes storage directories and loads accepted message IDs.
func NewStorage(dataDir string, maxUploadSize int64) (*Storage, error) {
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolving data directory: %w", err)
	}

	stagingDir := filepath.Join(absDataDir, ".staging")
	committingDir := filepath.Join(absDataDir, ".committing")
	docsDir := filepath.Join(absDataDir, "docs")
	outboxDir := filepath.Join(absDataDir, "outbox")
	inboxDir := filepath.Join(absDataDir, "inbox")
	acceptedFile := filepath.Join(absDataDir, "accepted.json")
	legacyReceiptsFile := filepath.Join(absDataDir, "accepted_receipts.json")

	for _, dir := range []string{absDataDir, stagingDir, committingDir, docsDir, outboxDir, inboxDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	s := &Storage{
		dataDir:            absDataDir,
		stagingDir:         stagingDir,
		committingDir:      committingDir,
		docsDir:            docsDir,
		outboxDir:          outboxDir,
		inboxDir:           inboxDir,
		acceptedFile:       acceptedFile,
		legacyReceiptsFile: legacyReceiptsFile,
		maxUploadSize:      maxUploadSize,
		acceptedIDs:        make(map[string]bool),
		acceptedReceipts:   make(map[string]string),
		inFlightUntil:      make(map[string]time.Time),
	}

	if err := s.loadAcceptedIDs(); err != nil {
		return nil, fmt.Errorf("loading accepted IDs: %w", err)
	}

	return s, nil
}

// StorageDirKey returns the collision-resistant internal directory key ("m-<sha256_hex>")
// for a valid protocol Message ID, keeping protocol IDs independent of case-insensitive
// or OS-reserved filesystem naming rules.
func StorageDirKey(id string) (string, error) {
	cleanID, err := sanitizeID(id)
	if err != nil {
		return "", err
	}
	return storageDirKey(cleanID), nil
}

func storageDirKey(cleanID string) string {
	sum := sha256.Sum256([]byte(cleanID))
	return "m-" + hex.EncodeToString(sum[:])
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

// sanitizeFilename strips directory elements and keeps only a safe base filename (rejecting ".", "..", and ".DS_Store").
func sanitizeFilename(name string) (string, error) {
	base := filepath.Base(filepath.Clean(name))
	if base == "." || base == ".." || base == "/" || base == "\\" || base == "" || base == ".DS_Store" || strings.Contains(base, "..") {
		return "", ErrTraversal
	}
	// Strip null bytes and control chars
	clean := strings.Map(func(r rune) rune {
		if r == 0 || r < 32 {
			return -1
		}
		return r
	}, base)
	if clean == "" || clean == "." || clean == ".." || clean == ".DS_Store" || strings.Contains(clean, "..") {
		return "", ErrTraversal
	}
	return clean, nil
}

// sanitizeID enforces the SPEC.md normative Message ID grammar:
// 1..128 ASCII characters in [a-zA-Z0-9._-], excluding ".", "..", and any ".." sequence.
func sanitizeID(id string) (string, error) {
	clean := strings.TrimSpace(id)
	if clean == "" || len(clean) > 128 || clean == "." || clean == ".." || strings.Contains(clean, "..") {
		return "", ErrInvalidID
	}
	for _, r := range clean {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
			return "", ErrInvalidID
		}
	}
	return clean, nil
}

// syncDir flushes directory metadata after file creation or rename and returns any synchronization error.
func syncDir(dirPath string) error {
	d, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// GenerateMessageID generates a cryptographically random, globally unique message ID.
func GenerateMessageID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("msg-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b))
}

func readMessageJSON(dirPath string) (*Message, error) {
	data, err := os.ReadFile(filepath.Join(dirPath, "message.json"))
	if err != nil {
		return nil, err
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	cleanID, err := sanitizeID(msg.ID)
	if err != nil || cleanID != msg.ID {
		return nil, ErrInvalidID
	}
	return &msg, nil
}

// resolveOutboxDirLocked resolves an outbox message directory by checking the primary
// collision-resistant key ("m-<sha256(id)>") first and falling back to a legacy "<id>" path
// only if its stored message.json has an exact case-sensitive ID match.
func (s *Storage) resolveOutboxDirLocked(cleanID string) (string, *Message, error) {
	dirKey := storageDirKey(cleanID)
	primaryDir := filepath.Join(s.outboxDir, dirKey)
	if fi, err := os.Stat(primaryDir); err == nil && fi.IsDir() {
		msg, readErr := readMessageJSON(primaryDir)
		if readErr != nil {
			return primaryDir, nil, readErr
		}
		if msg.ID != cleanID {
			return primaryDir, nil, ErrStorageCollision
		}
		return primaryDir, msg, nil
	} else if err != nil && !os.IsNotExist(err) {
		return primaryDir, nil, err
	}

	if cleanID != dirKey {
		legacyDir := filepath.Join(s.outboxDir, cleanID)
		if fi, err := os.Stat(legacyDir); err == nil && fi.IsDir() {
			msg, readErr := readMessageJSON(legacyDir)
			if readErr != nil {
				return legacyDir, nil, readErr
			}
			if msg.ID != cleanID {
				// Belongs to a different case-variant legacy directory on a case-insensitive filesystem
				return "", nil, ErrNotFound
			}
			return legacyDir, msg, nil
		} else if err != nil && !os.IsNotExist(err) {
			return legacyDir, nil, err
		}
	}

	return "", nil, ErrNotFound
}

// resolveInboxDirLocked resolves an inbox message directory by checking the primary
// collision-resistant key ("m-<sha256(id)>") first, then `.committing/m-<sha256(id)>` (if already
// committed in acceptedIDs), and finally a legacy "<id>" path with exact ID verification.
func (s *Storage) resolveInboxDirLocked(cleanID string) (string, *Message, error) {
	dirKey := storageDirKey(cleanID)
	primaryDir := filepath.Join(s.inboxDir, dirKey)
	if fi, err := os.Stat(primaryDir); err == nil && fi.IsDir() {
		msg, readErr := readMessageJSON(primaryDir)
		if readErr != nil {
			return primaryDir, nil, readErr
		}
		if msg.ID != cleanID {
			return primaryDir, nil, ErrStorageCollision
		}
		return primaryDir, msg, nil
	} else if err != nil && !os.IsNotExist(err) {
		return primaryDir, nil, err
	}

	if s.acceptedIDs[cleanID] {
		committingPath := filepath.Join(s.committingDir, dirKey)
		if fi, err := os.Stat(committingPath); err == nil && fi.IsDir() {
			msg, readErr := readMessageJSON(committingPath)
			if readErr != nil {
				return committingPath, nil, readErr
			}
			if msg.ID != cleanID {
				return committingPath, nil, ErrStorageCollision
			}
			return committingPath, msg, nil
		}
	}

	if cleanID != dirKey {
		legacyDir := filepath.Join(s.inboxDir, cleanID)
		if fi, err := os.Stat(legacyDir); err == nil && fi.IsDir() {
			msg, readErr := readMessageJSON(legacyDir)
			if readErr != nil {
				return legacyDir, nil, readErr
			}
			if msg.ID != cleanID {
				return "", nil, ErrNotFound
			}
			return legacyDir, msg, nil
		} else if err != nil && !os.IsNotExist(err) {
			return legacyDir, nil, err
		}
	}

	return "", nil, ErrNotFound
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
		if entry.IsDir() || entry.Name() == ".DS_Store" {
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
	nameHash := sha256.Sum256([]byte(cleanName))
	tmpPath := filepath.Join(s.stagingDir, fmt.Sprintf("doc-%s-%d", hex.EncodeToString(nameHash[:8]), time.Now().UnixNano()))

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
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
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := syncDir(s.stagingDir); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := syncDir(s.docsDir); err != nil {
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
	if fi, err := os.Lstat(targetPath); err != nil || !fi.Mode().IsRegular() {
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
	if payload == nil {
		payload = map[string]any{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	msgID := GenerateMessageID()
	dirKey := storageDirKey(msgID)
	msgDir := filepath.Join(s.outboxDir, dirKey)
	if _, err := os.Stat(msgDir); err == nil {
		return nil, ErrStorageCollision
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	tmpDir := filepath.Join(s.stagingDir, fmt.Sprintf("outbox-%s-%d", dirKey, time.Now().UnixNano()))
	attachmentsDir := filepath.Join(tmpDir, "attachments")

	if err := os.MkdirAll(attachmentsDir, 0700); err != nil {
		return nil, err
	}

	var attachments []AttachmentInfo
	seenNames := make(map[string]bool)

	// Copy selected documents into staging snapshot directory using O_EXCL to detect filesystem collisions
	for _, rawName := range docNames {
		cleanName, err := sanitizeFilename(rawName)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if seenNames[cleanName] {
			_ = os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
		}
		seenNames[cleanName] = true

		srcPath := filepath.Join(s.docsDir, cleanName)
		if fi, err := os.Lstat(srcPath); err != nil || !fi.Mode().IsRegular() {
			_ = os.RemoveAll(tmpDir)
			if err != nil && os.IsNotExist(err) {
				return nil, fmt.Errorf("attachment %s does not exist: %w", cleanName, ErrNotFound)
			}
			return nil, ErrTraversal
		}
		srcFile, err := os.Open(srcPath)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("attachment %s does not exist: %w", cleanName, ErrNotFound)
			}
			return nil, err
		}

		dstPath := filepath.Join(attachmentsDir, cleanName)
		dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			_ = srcFile.Close()
			_ = os.RemoveAll(tmpDir)
			if errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
			}
			return nil, err
		}

		hasher := sha256.New()
		writer := io.MultiWriter(dstFile, hasher)
		n, err := io.Copy(writer, srcFile)
		_ = srcFile.Close()
		if err != nil {
			_ = dstFile.Close()
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if err := dstFile.Sync(); err != nil {
			_ = dstFile.Close()
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if err := dstFile.Close(); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}

		attachments = append(attachments, AttachmentInfo{
			Name:   cleanName,
			Size:   n,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
	}
	if err := syncDir(attachmentsDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	sigHex, err := SignPutMessage(s.ownPrivKey, s.role, s.peerRole, msgID, payload, attachments)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	msg := &Message{
		ID:          msgID,
		CreatedAt:   time.Now().UTC(),
		Payload:     payload,
		Attachments: attachments,
		Signature:   sigHex,
	}

	if _, err := s.writeAtomicJSONWithCommitState(filepath.Join(tmpDir, "message.json"), msg); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := syncDir(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := syncDir(s.stagingDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	if err := os.Rename(tmpDir, msgDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := syncDir(s.outboxDir); err != nil {
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
	seenIDs := make(map[string]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		msgDir := filepath.Join(s.outboxDir, dirName)
		msg, err := readMessageJSON(msgDir)
		if err != nil {
			continue
		}
		// Accept both collision-resistant internal keys ("m-<sha256(id)>") and legacy/external "<id>" directories
		// whose message.json matches the directory name.
		if dirName != storageDirKey(msg.ID) && !strings.EqualFold(dirName, msg.ID) {
			continue
		}
		if seenIDs[msg.ID] {
			continue
		}

		// File-spool safety: verify all declared attachments exist as regular files with matching size
		// before offering the message (prevents offering a message while an external writer is still copying files).
		complete := true
		for _, att := range msg.Attachments {
			cleanAtt, err := sanitizeFilename(att.Name)
			if err != nil {
				complete = false
				break
			}
			attPath := filepath.Join(msgDir, "attachments", cleanAtt)
			fi, err := os.Lstat(attPath)
			if err != nil || !fi.Mode().IsRegular() || fi.Size() != att.Size {
				complete = false
				break
			}
		}
		if !complete {
			continue
		}
		seenIDs[msg.ID] = true
		if leaseUntil, ok := s.inFlightUntil[msg.ID]; ok && now.Before(leaseUntil) {
			inFlight = append(inFlight, msg)
		} else {
			unclaimed = append(unclaimed, msg)
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

	_, msg, err := s.resolveOutboxDirLocked(cleanID)
	if err != nil {
		return nil, err
	}
	s.inFlightUntil[cleanID] = time.Now().Add(OutboxLeaseDuration)
	return msg, nil
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

	msgDir, _, err := s.resolveOutboxDirLocked(cleanID)
	if err != nil {
		return "", err
	}

	filePath := filepath.Join(msgDir, "attachments", cleanFile)
	if fi, err := os.Lstat(filePath); err != nil || !fi.Mode().IsRegular() {
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
		msgDir, _, resolveErr := s.resolveOutboxDirLocked(cleanID)
		delete(s.inFlightUntil, cleanID)
		if resolveErr == nil && msgDir != "" {
			_ = os.RemoveAll(msgDir)
		}
	}
	return nil
}

// AcknowledgeMessagesVerified removes acknowledged messages from outbox (Rule 6),
// strictly verifying cryptographic ACK receipts against the peer's public key (fail-closed)
// whenever a peer public key is configured.
func (s *Storage) AcknowledgeMessagesVerified(ids []string, receipts map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	removedAny := false
	for _, rawID := range ids {
		cleanID, err := sanitizeID(rawID)
		if err != nil {
			continue
		}
		msgDir, outMsg, resolveErr := s.resolveOutboxDirLocked(cleanID)
		if len(s.peerPubKey) > 0 {
			if resolveErr != nil {
				if errors.Is(resolveErr, ErrNotFound) {
					delete(s.inFlightUntil, cleanID)
					continue
				}
				return fmt.Errorf("reading outbox message %s for receipt verification: %w", cleanID, resolveErr)
			}
			if strings.TrimSpace(outMsg.Signature) == "" {
				return fmt.Errorf("unsigned outbox message %s cannot be verified: %w", cleanID, ErrInvalidSignature)
			}
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
		} else if resolveErr != nil && !errors.Is(resolveErr, ErrNotFound) {
			return fmt.Errorf("reading outbox message %s: %w", cleanID, resolveErr)
		}

		delete(s.inFlightUntil, cleanID)
		if resolveErr == nil && msgDir != "" {
			if err := os.RemoveAll(msgDir); err != nil {
				return err
			}
			removedAny = true
		}
	}
	if removedAny {
		if err := syncDir(s.outboxDir); err != nil {
			return err
		}
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

// ListAcceptedReceipts returns a map of accepted message ID -> cryptographic ACK receipt from the authoritative index.
func (s *Storage) ListAcceptedReceipts() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	receipts := make(map[string]string, len(s.acceptedIDs))
	for id := range s.acceptedIDs {
		if r, ok := s.acceptedReceipts[id]; ok && r != "" {
			receipts[id] = r
			continue
		}
		if _, m, err := s.resolveInboxDirLocked(id); err == nil && m != nil && m.AckReceipt != "" {
			receipts[id] = m.AckReceipt
			continue
		}
		receipts[id] = ""
	}
	return receipts
}

// ListInbox returns all accepted messages currently stored in inbox.
func (s *Storage) ListInbox() ([]*Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.inboxDir)
	if err != nil {
		return nil, err
	}

	var msgs []*Message
	seenIDs := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		msg, err := readMessageJSON(filepath.Join(s.inboxDir, dirName))
		if err != nil {
			continue
		}
		if dirName != storageDirKey(msg.ID) && !strings.EqualFold(dirName, msg.ID) {
			continue
		}
		if !s.acceptedIDs[msg.ID] || seenIDs[msg.ID] {
			continue
		}
		seenIDs[msg.ID] = true
		msgs = append(msgs, msg)
	}

	// Include any committed message still awaiting final move from .committing/
	if commEntries, err := os.ReadDir(s.committingDir); err == nil {
		for _, entry := range commEntries {
			if !entry.IsDir() {
				continue
			}
			dirName := entry.Name()
			msg, err := readMessageJSON(filepath.Join(s.committingDir, dirName))
			if err != nil {
				continue
			}
			if dirName == storageDirKey(msg.ID) && s.acceptedIDs[msg.ID] && !seenIDs[msg.ID] {
				seenIDs[msg.ID] = true
				msgs = append(msgs, msg)
			}
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

	if !s.acceptedIDs[cleanID] {
		return nil, ErrNotFound
	}
	_, msg, err := s.resolveInboxDirLocked(cleanID)
	if err != nil {
		return nil, err
	}
	return msg, nil
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

	if !s.acceptedIDs[cleanID] {
		return "", ErrNotFound
	}
	msgDir, _, err := s.resolveInboxDirLocked(cleanID)
	if err != nil {
		return "", err
	}

	filePath := filepath.Join(msgDir, "attachments", cleanFile)
	if fi, err := os.Lstat(filePath); err != nil || !fi.Mode().IsRegular() {
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
	if payload == nil {
		payload = map[string]any{}
	}

	cleanID, err := sanitizeID(id)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dirKey := storageDirKey(cleanID)
	committingPath := filepath.Join(s.committingDir, dirKey)
	targetDir := filepath.Join(s.inboxDir, dirKey)

	// 1. Duplicate check: if already accepted in the authoritative index, verify signature match (when required)
	//    and return the stored message / receipt without re-importing or overwriting anything.
	if s.acceptedIDs[cleanID] {
		msgDir, existing, resolveErr := s.resolveInboxDirLocked(cleanID)
		if resolveErr == nil && existing != nil {
			if (requireSignature || sigHex != "") && len(s.peerPubKey) > 0 {
				if existing.Signature == "" || !strings.EqualFold(strings.TrimSpace(existing.Signature), strings.TrimSpace(sigHex)) {
					return nil, ErrInvalidSignature
				}
			}
			// If the message was still sitting in .committing/ after an interrupted final move, finish moving it now
			if msgDir == committingPath {
				if _, statErr := os.Stat(targetDir); os.IsNotExist(statErr) {
					if renErr := os.Rename(committingPath, targetDir); renErr == nil {
						_ = syncDir(s.inboxDir)
						_ = syncDir(s.committingDir)
					}
				}
			}
			return existing, nil
		}

		// Inbox directory may have been archived/deleted by an external hot-folder consumer after commit.
		// Verify signature match against the stored signed ACK receipt when keys are configured.
		storedReceipt := s.acceptedReceipts[cleanID]
		if (requireSignature || sigHex != "") && len(s.peerPubKey) > 0 {
			if strings.TrimSpace(sigHex) == "" || len(s.ownPubKey) == 0 || storedReceipt == "" {
				return nil, ErrInvalidSignature
			}
			if err := VerifyAckReceipt(s.ownPubKey, s.role, cleanID, strings.TrimSpace(sigHex), storedReceipt); err != nil {
				return nil, ErrInvalidSignature
			}
		}
		return &Message{
			ID:         cleanID,
			Payload:    payload,
			Signature:  sigHex,
			AckReceipt: storedReceipt,
		}, nil
	}

	// 2. Pre-check destination directories before staging. NEVER call RemoveAll on an existing inbox directory:
	//    reject any hash/filesystem collision without touching existing contents.
	if _, statErr := os.Stat(targetDir); statErr == nil {
		existing, readErr := readMessageJSON(targetDir)
		if readErr != nil || existing.ID != cleanID {
			return nil, ErrStorageCollision
		}
		if (requireSignature || sigHex != "") && len(s.peerPubKey) > 0 {
			if existing.Signature == "" || !strings.EqualFold(strings.TrimSpace(existing.Signature), strings.TrimSpace(sigHex)) {
				return nil, ErrInvalidSignature
			}
		}
		s.acceptedIDs[cleanID] = true
		s.acceptedReceipts[cleanID] = existing.AckReceipt
		if committed, pErr := s.persistAcceptedIDsLocked(); pErr != nil {
			if !committed {
				delete(s.acceptedIDs, cleanID)
				delete(s.acceptedReceipts, cleanID)
			}
			return nil, fmt.Errorf("persisting accepted ID: %w", pErr)
		}
		return existing, nil
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	if _, statErr := os.Stat(committingPath); statErr == nil {
		existing, readErr := readMessageJSON(committingPath)
		if readErr == nil && existing.ID != cleanID {
			return nil, ErrStorageCollision
		}
		// Only remove an uncommitted .committing directory if it does NOT belong to a different ID
		if err := os.RemoveAll(committingPath); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	// 3. Stage files and message.json inside dedicated .staging/ namespace: all-or-nothing
	tmpDir := filepath.Join(s.stagingDir, fmt.Sprintf("inbox-%s-%d", dirKey, time.Now().UnixNano()))
	tmpAttachmentsDir := filepath.Join(tmpDir, "attachments")
	if err := os.MkdirAll(tmpAttachmentsDir, 0700); err != nil {
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
		// Use O_EXCL so case-insensitive or Unicode-normalizing filesystems never overwrite an existing attachment
		dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			if errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
			}
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
		if err := dstFile.Close(); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}

		attInfos = append(attInfos, AttachmentInfo{
			Name:   cleanName,
			Size:   n,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})
	}
	if err := syncDir(tmpAttachmentsDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	// Enforce Ed25519 signature verification when required and peer public key is configured
	if (requireSignature || sigHex != "") && len(s.peerPubKey) > 0 {
		if err := VerifyPutMessage(s.peerPubKey, s.peerRole, s.role, cleanID, payload, attInfos, sigHex); err != nil {
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

	if _, err := s.writeAtomicJSONWithCommitState(filepath.Join(tmpDir, "message.json"), msg); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := syncDir(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := syncDir(s.stagingDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	// 4. Move staged message to .committing/m-<sha256(id)> (not yet visible in inbox/ to external consumers).
	if err := os.Rename(tmpDir, committingPath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := syncDir(s.committingDir); err != nil {
		_ = os.RemoveAll(committingPath)
		return nil, err
	}

	// 5. Authoritative Commit Point: atomically persist consolidated accepted.json (id -> ackReceipt)
	//    BEFORE exposing the directory inside inbox/.
	s.acceptedIDs[cleanID] = true
	s.acceptedReceipts[cleanID] = ackReceipt
	committedOnDisk, err := s.persistAcceptedIDsLocked()
	if err != nil {
		if !committedOnDisk {
			// accepted.json on disk was NOT modified; roll back cleanly so state stays 100% unaccepted
			delete(s.acceptedIDs, cleanID)
			delete(s.acceptedReceipts, cleanID)
			_ = os.RemoveAll(committingPath)
			_ = syncDir(s.committingDir)
			return nil, fmt.Errorf("persisting accepted ID: %w", err)
		}
		// accepted.json rename succeeded on disk (only parent dir sync failed): NEVER delete the committed message.
		_ = os.Rename(committingPath, targetDir)
		return nil, fmt.Errorf("syncing accepted ID index: %w", err)
	}

	// 6. Expose committed message in inbox/m-<sha256(id)> now that accepted.json is durable on disk.
	//    Never delete committingPath or revoke acceptedIDs if this post-commit step encounters an error.
	if err := os.Rename(committingPath, targetDir); err != nil {
		return nil, fmt.Errorf("moving committed message into inbox: %w", err)
	}
	if err := syncDir(s.inboxDir); err != nil {
		return nil, err
	}
	_ = syncDir(s.committingDir)

	return msg, nil
}

// -----------------------------------------------------------------------------
// Persistence & Recovery Helpers
// -----------------------------------------------------------------------------

func (s *Storage) loadAcceptedIDs() error {
	// 1. Purge dedicated .staging directory from prior interrupted runs.
	_ = os.RemoveAll(s.stagingDir)
	if err := os.MkdirAll(s.stagingDir, 0700); err != nil {
		return err
	}

	needsPersist := false
	removeLegacyReceipts := false

	// 2. Load consolidated accepted.json (map[string]string of id -> ackReceipt),
	//    supporting legacy []string format transparently.
	data, err := os.ReadFile(s.acceptedFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		var mapFormat map[string]string
		if err := json.Unmarshal(data, &mapFormat); err == nil && mapFormat != nil {
			for id, receipt := range mapFormat {
				if clean, err := sanitizeID(id); err == nil {
					s.acceptedIDs[clean] = true
					if receipt != "" {
						s.acceptedReceipts[clean] = receipt
					}
				}
			}
		} else {
			var legacyList []string
			if err := json.Unmarshal(data, &legacyList); err != nil {
				return err
			}
			for _, id := range legacyList {
				if clean, err := sanitizeID(id); err == nil {
					s.acceptedIDs[clean] = true
				}
			}
			needsPersist = true
		}
	}

	// 3. Merge legacy accepted_receipts.json if present (preserving receipts even for messages
	//    whose inbox directories were already archived/deleted by external consumers).
	if rData, err := os.ReadFile(s.legacyReceiptsFile); err == nil {
		var rMap map[string]string
		if err := json.Unmarshal(rData, &rMap); err != nil {
			return err
		}
		for id, receipt := range rMap {
			if clean, err := sanitizeID(id); err == nil {
				s.acceptedIDs[clean] = true
				if receipt != "" && s.acceptedReceipts[clean] == "" {
					s.acceptedReceipts[clean] = receipt
				}
			}
		}
		needsPersist = true
		removeLegacyReceipts = true
	} else if !os.IsNotExist(err) {
		return err
	}

	// 4. Reconcile .committing/:
	//    - If msg.ID is in acceptedIDs (crash happened AFTER accepted.json commit, BEFORE inbox rename),
	//      complete the move into inbox/m-<sha256(id)>.
	//    - Otherwise (crash happened BEFORE accepted.json commit; never acknowledged or exposed),
	//      remove the uncommitted directory.
	if commEntries, err := os.ReadDir(s.committingDir); err == nil {
		commChanged := false
		inboxChanged := false
		for _, entry := range commEntries {
			commPath := filepath.Join(s.committingDir, entry.Name())
			if !entry.IsDir() {
				_ = os.RemoveAll(commPath)
				commChanged = true
				continue
			}
			msg, readErr := readMessageJSON(commPath)
			if readErr == nil && entry.Name() == storageDirKey(msg.ID) && s.acceptedIDs[msg.ID] {
				if msg.AckReceipt != "" && s.acceptedReceipts[msg.ID] == "" {
					s.acceptedReceipts[msg.ID] = msg.AckReceipt
					needsPersist = true
				}
				dstInbox := filepath.Join(s.inboxDir, entry.Name())
				if _, statErr := os.Stat(dstInbox); os.IsNotExist(statErr) {
					if renErr := os.Rename(commPath, dstInbox); renErr != nil {
						return renErr
					}
					commChanged = true
					inboxChanged = true
				} else if statErr == nil {
					_ = os.RemoveAll(commPath)
					commChanged = true
				}
			} else {
				_ = os.RemoveAll(commPath)
				commChanged = true
			}
		}
		if inboxChanged {
			if err := syncDir(s.inboxDir); err != nil {
				return err
			}
		}
		if commChanged {
			if err := syncDir(s.committingDir); err != nil {
				return err
			}
		}
	}

	// 5. Reconcile committed inbox/ directories (both "m-<sha256(id)>" and legacy "<id>" directories)
	//    into acceptedIDs and acceptedReceipts.
	if entries, err := os.ReadDir(s.inboxDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dirName := entry.Name()
			msg, readErr := readMessageJSON(filepath.Join(s.inboxDir, dirName))
			if readErr != nil {
				continue
			}
			if dirName != storageDirKey(msg.ID) && !strings.EqualFold(dirName, msg.ID) {
				continue
			}
			if msg.AckReceipt != "" && s.acceptedReceipts[msg.ID] == "" {
				s.acceptedReceipts[msg.ID] = msg.AckReceipt
				needsPersist = true
			}
			if !s.acceptedIDs[msg.ID] {
				s.acceptedIDs[msg.ID] = true
				needsPersist = true
			}
		}
	}

	if needsPersist {
		if _, err := s.persistAcceptedIDsLocked(); err != nil {
			return err
		}
	}
	if removeLegacyReceipts {
		_ = os.Remove(s.legacyReceiptsFile)
		_ = syncDir(s.dataDir)
	}
	return nil
}

func (s *Storage) persistAcceptedIDsLocked() (bool, error) {
	consolidated := make(map[string]string, len(s.acceptedIDs))
	for id := range s.acceptedIDs {
		consolidated[id] = s.acceptedReceipts[id]
	}
	return s.writeAtomicJSONWithCommitState(s.acceptedFile, consolidated)
}

func (s *Storage) writeAtomicJSONWithCommitState(targetPath string, v any) (bool, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return false, err
	}

	nameSum := sha256.Sum256([]byte(filepath.Base(targetPath)))
	tmpPath := filepath.Join(s.stagingDir, fmt.Sprintf("json-%s-%d", hex.EncodeToString(nameSum[:8]), time.Now().UnixNano()))
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return false, err
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return false, err
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return false, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	if err := syncDir(s.stagingDir); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	if err := syncDir(filepath.Dir(targetPath)); err != nil {
		return true, err
	}
	return true, nil
}
