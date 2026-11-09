package umaispool

import (
	"bytes"
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
	MaxBatchIDs              = 1000
	DefaultMaxUploadSize     = 100 * 1024 * 1024
	OutboxLeaseDuration      = 15 * time.Second
)

var (
	ErrNotFound              = errors.New("not found")
	ErrInvalidID             = errors.New("invalid identifier")
	ErrAlreadyAccepted       = errors.New("message already accepted")
	ErrConflictingDuplicate  = errors.New("conflicting message content for already-accepted ID")
	ErrInvalidAttachmentMeta = errors.New("invalid attachment_meta: must match uploaded attachments 1:1 without duplicates")
	ErrTraversal             = errors.New("invalid file path / directory traversal detected")
	ErrFileTooLarge          = errors.New("file exceeds maximum allowed size")
	ErrDuplicateAttachment   = errors.New("duplicate attachment filename in message")
	ErrTooManyAttachments    = errors.New("too many attachments in message")
	ErrTooManyIDs            = errors.New("batch exceeds maximum allowed message IDs")
	ErrStorageCollision      = errors.New("storage directory collision detected")
	ErrAlreadyPublished      = errors.New("message ID already published in outbox")
)

const (
	unsignedDigestSender   = "umai:unsigned:sender"
	unsignedDigestReceiver = "umai:unsigned:receiver"
)

// AttachmentInfo describes a binary attachment belonging to a message.
type AttachmentInfo struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type,omitempty"`
}

// AcceptedRecord is the durable per-ID acceptance entry persisted in accepted.json.
type AcceptedRecord struct {
	AcceptedAt time.Time `json:"accepted_at"`
	AckReceipt string    `json:"ack_receipt,omitempty"`
	Digest     string    `json:"digest"`
}

// Message represents an immutable UMAI message stored in outbox or inbox.
type Message struct {
	ID          string           `json:"id"`
	CreatedAt   *time.Time       `json:"created_at,omitempty"`
	AcceptedAt  *time.Time       `json:"accepted_at,omitempty"`
	Payload     any              `json:"payload"`
	Attachments []AttachmentInfo `json:"attachments"`
	Signature   string           `json:"signature,omitempty"`
	AckReceipt  string           `json:"ack_receipt,omitempty"`
	Digest      string           `json:"digest,omitempty"`
}

// AttachmentReader encapsulates an attachment stream for outbox publication or inbox acceptance.
type AttachmentReader struct {
	Name      string
	MediaType string
	Reader    io.Reader
}

// SigningConfig configures the explicit local/peer logical identities and Ed25519 keys for a spool instance.
type SigningConfig struct {
	LocalIdentity string
	PeerIdentity  string
	PrivateKey    ed25519.PrivateKey
	PeerPublicKey ed25519.PublicKey
}

// Storage manages immutable outbox snapshots, atomic inbox commits, and durable accepted ID records.
//
// Process Ownership & Directory Model:
//   - A single spool server process per `dataDir` opens `Storage` and exclusively owns `.staging/`,
//     `.committing/`, `accepted.json`, `inbox/` commits, and startup crash recovery.
//   - External producers (see `Publish` and `cmd/umai-spool`) stage outgoing messages exclusively inside
//     the producer-owned `prepare/` directory and atomically rename completed directories into `outbox/m-<sha256(id)>/`.
//     Server startup (`NewStorage`) never purges or modifies `prepare/`.
//   - Incoming commit sequence:
//     1. Incoming files and message.json are written and fsynced in `.staging/`.
//     2. The staged directory is atomically renamed to `.committing/m-<sha256(id)>/` (invisible to `inbox/` consumers).
//     3. `accepted.json` (`id -> {accepted_at, ack_receipt, digest}`) is atomically updated and its parent directory (`dataDir`) is fsynced.
//     4. Only AFTER both `accepted.json` and `dataDir` are durable on disk is `.committing/m-<sha256(id)>/` renamed
//     into `inbox/m-<sha256(id)>/` and `inboxDir` fsynced, promoting the ID from `pendingCommits` to `acceptedRecords`.
type Storage struct {
	mu                sync.RWMutex
	dataDir           string
	stagingDir        string
	committingDir     string
	outboxDir         string
	inboxDir          string
	acceptedFile      string
	maxUploadSize     int64
	acceptedRecords   map[string]AcceptedRecord
	pendingCommits    map[string]*Message
	inFlightUntil     map[string]time.Time
	syncDirFn         func(string) error
	signingConfigured bool
	localIdentity     string
	peerIdentity      string
	ownPubKey         ed25519.PublicKey
	ownPrivKey        ed25519.PrivateKey
	peerPubKey        ed25519.PublicKey
}

// NewStorage initializes spool directories and recovers durable accepted message IDs.
func NewStorage(dataDir string, maxUploadSize int64) (*Storage, error) {
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolving data directory: %w", err)
	}
	if maxUploadSize <= 0 {
		maxUploadSize = DefaultMaxUploadSize
	}

	stagingDir := filepath.Join(absDataDir, ".staging")
	committingDir := filepath.Join(absDataDir, ".committing")
	prepareDir := filepath.Join(absDataDir, "prepare")
	outboxDir := filepath.Join(absDataDir, "outbox")
	inboxDir := filepath.Join(absDataDir, "inbox")
	acceptedFile := filepath.Join(absDataDir, "accepted.json")

	for _, dir := range []string{absDataDir, stagingDir, committingDir, prepareDir, outboxDir, inboxDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	s := &Storage{
		dataDir:         absDataDir,
		stagingDir:      stagingDir,
		committingDir:   committingDir,
		outboxDir:       outboxDir,
		inboxDir:        inboxDir,
		acceptedFile:    acceptedFile,
		maxUploadSize:   maxUploadSize,
		acceptedRecords: make(map[string]AcceptedRecord),
		pendingCommits:  make(map[string]*Message),
		inFlightUntil:   make(map[string]time.Time),
		syncDirFn:       SyncDir,
	}

	if err := s.loadAcceptedIDs(); err != nil {
		return nil, fmt.Errorf("loading accepted IDs: %w", err)
	}

	return s, nil
}

// DataDir returns the resolved absolute root directory of this spool.
func (s *Storage) DataDir() string {
	return s.dataDir
}

// MaxUploadSize returns the configured per-attachment byte limit.
func (s *Storage) MaxUploadSize() int64 {
	return s.maxUploadSize
}

// SetSyncDirForTesting overrides the directory-synchronization function (pass nil to restore default os.File.Sync).
func (s *Storage) SetSyncDirForTesting(fn func(string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fn == nil {
		s.syncDirFn = SyncDir
	} else {
		s.syncDirFn = fn
	}
}

func (s *Storage) syncDirLocked(dirPath string) error {
	if s.syncDirFn != nil {
		return s.syncDirFn(dirPath)
	}
	return SyncDir(dirPath)
}

// SetSigningConfig configures the explicit local and peer identities and Ed25519 keys.
func (s *Storage) SetSigningConfig(cfg SigningConfig) error {
	localTrim := strings.TrimSpace(cfg.LocalIdentity)
	peerTrim := strings.TrimSpace(cfg.PeerIdentity)
	if localTrim == "" || peerTrim == "" {
		return ErrMissingIdentity
	}
	if localTrim != cfg.LocalIdentity || peerTrim != cfg.PeerIdentity || localTrim == peerTrim {
		return ErrInvalidIdentity
	}
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize || len(cfg.PeerPublicKey) != ed25519.PublicKeySize {
		return ErrSigningNotConfigured
	}

	ownPriv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(ownPriv, cfg.PrivateKey)
	ownPub := ownPriv.Public().(ed25519.PublicKey)

	peerPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(peerPub, cfg.PeerPublicKey)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.localIdentity = localTrim
	s.peerIdentity = peerTrim
	s.ownPubKey = ownPub
	s.ownPrivKey = ownPriv
	s.peerPubKey = peerPub
	s.signingConfigured = true

	// Backfill any recovered record whose Digest was empty at startup (before identities were configured).
	for id, rec := range s.acceptedRecords {
		if rec.Digest == "" {
			if _, existing, err := s.resolveInboxDirLocked(id); err == nil && existing != nil {
				if d, dErr := s.computeIncomingDigestLocked(id, existing.Payload, existing.Attachments); dErr == nil {
					rec.Digest = d
					s.acceptedRecords[id] = rec
				}
			}
		}
	}
	return nil
}

func (s *Storage) computeIncomingDigestLocked(cleanID string, payload any, attInfos []AttachmentInfo) (string, error) {
	sender := s.peerIdentity
	receiver := s.localIdentity
	if !s.signingConfigured {
		sender = unsignedDigestSender
		receiver = unsignedDigestReceiver
	}
	digest, err := CanonicalPutDigest(sender, receiver, cleanID, payload, attInfos)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

// HasSigningConfig reports whether explicit identities and Ed25519 signing/verification keys are configured.
func (s *Storage) HasSigningConfig() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.signingConfigured
}

// LocalIdentity returns the configured local logical identity.
func (s *Storage) LocalIdentity() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localIdentity
}

// PeerIdentity returns the configured peer logical identity.
func (s *Storage) PeerIdentity() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerIdentity
}

// PublicKeyHex returns this spool's Ed25519 public key in hex.
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

// StorageDirKey returns the collision-resistant internal directory key ("m-<sha256_hex>")
// for a valid protocol Message ID, keeping protocol IDs independent of case-insensitive
// or OS-reserved filesystem naming rules.
func StorageDirKey(id string) (string, error) {
	cleanID, err := SanitizeID(id)
	if err != nil {
		return "", err
	}
	return storageDirKey(cleanID), nil
}

func storageDirKey(cleanID string) string {
	sum := sha256.Sum256([]byte(cleanID))
	return "m-" + hex.EncodeToString(sum[:])
}

// SanitizeFilename strips directory elements and keeps only a safe base filename (rejecting ".", "..", and ".DS_Store").
func SanitizeFilename(name string) (string, error) {
	base := filepath.Base(filepath.Clean(name))
	if base == "." || base == ".." || base == "/" || base == "\\" || base == "" || base == ".DS_Store" || strings.Contains(base, "..") {
		return "", ErrTraversal
	}
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

// SanitizeID enforces the SPEC.md normative Message ID grammar:
// 1..128 ASCII characters in [a-zA-Z0-9._-], excluding ".", "..", and any ".." sequence.
func SanitizeID(id string) (string, error) {
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

// SyncDir flushes directory metadata after file creation or rename and returns any synchronization error.
func SyncDir(dirPath string) error {
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
	return fmt.Sprintf("msg-%d-%s", time.Now().UTC().UnixMilli(), hex.EncodeToString(b))
}

func readMessageJSON(dirPath string) (*Message, error) {
	data, err := os.ReadFile(filepath.Join(dirPath, "message.json"))
	if err != nil {
		return nil, err
	}
	var msg Message
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	cleanID, err := SanitizeID(msg.ID)
	if err != nil || cleanID != msg.ID {
		return nil, ErrInvalidID
	}
	for i := range msg.Attachments {
		cleanMedia, mErr := ValidateMediaType(msg.Attachments[i].MediaType)
		if mErr != nil {
			return nil, mErr
		}
		msg.Attachments[i].MediaType = cleanMedia
	}
	if msg.CreatedAt != nil {
		utc := msg.CreatedAt.UTC()
		msg.CreatedAt = &utc
	}
	if msg.AcceptedAt != nil {
		utc := msg.AcceptedAt.UTC()
		msg.AcceptedAt = &utc
	}
	return &msg, nil
}

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
	return "", nil, ErrNotFound
}

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
	return "", nil, ErrNotFound
}

// -----------------------------------------------------------------------------
// Outbox Management (Rule 1: Immutability & Snapshots)
// -----------------------------------------------------------------------------

// CreateOutboxMessage creates an immutable message snapshot in outboxDir from attachment readers.
func (s *Storage) CreateOutboxMessage(payload any, attachments []AttachmentReader) (*Message, error) {
	return s.CreateOutboxMessageWithID("", payload, attachments)
}

// CreateOutboxMessageWithID creates an immutable message snapshot in outboxDir using an explicit
// Message ID (or auto-generating one if id is empty). Never overwrites an existing outbox message.
func (s *Storage) CreateOutboxMessageWithID(id string, payload any, attachments []AttachmentReader) (*Message, error) {
	if len(attachments) > MaxAttachmentsPerMessage {
		return nil, ErrTooManyAttachments
	}
	if payload == nil {
		payload = map[string]any{}
	}

	var msgID string
	if strings.TrimSpace(id) == "" {
		msgID = GenerateMessageID()
	} else {
		cleanID, err := SanitizeID(id)
		if err != nil {
			return nil, err
		}
		msgID = cleanID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	dirKey := storageDirKey(msgID)
	msgDir := filepath.Join(s.outboxDir, dirKey)
	if _, err := os.Stat(msgDir); err == nil {
		if existing, rErr := readMessageJSON(msgDir); rErr == nil && existing.ID != msgID {
			return nil, ErrStorageCollision
		}
		return nil, ErrAlreadyPublished
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	tmpDir := filepath.Join(s.stagingDir, fmt.Sprintf("outbox-%s-%d", dirKey, time.Now().UTC().UnixNano()))
	attachmentsDir := filepath.Join(tmpDir, "attachments")
	if err := os.MkdirAll(attachmentsDir, 0700); err != nil {
		return nil, err
	}

	var attInfos []AttachmentInfo
	seenNames := make(map[string]bool)

	for _, att := range attachments {
		cleanName, err := SanitizeFilename(att.Name)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		cleanMedia, err := ValidateMediaType(att.MediaType)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if seenNames[cleanName] {
			_ = os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
		}
		seenNames[cleanName] = true
		if att.Reader == nil {
			_ = os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("nil reader for attachment %s", cleanName)
		}

		dstPath := filepath.Join(attachmentsDir, cleanName)
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
			Name:      cleanName,
			Size:      n,
			SHA256:    hex.EncodeToString(hasher.Sum(nil)),
			MediaType: cleanMedia,
		})
	}

	if err := s.syncDirLocked(attachmentsDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	sigHex := ""
	if s.signingConfigured {
		var err error
		sigHex, err = SignPutMessage(s.ownPrivKey, s.localIdentity, s.peerIdentity, msgID, payload, attInfos)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
	}

	createdAt := time.Now().UTC()
	msg := &Message{
		ID:          msgID,
		CreatedAt:   &createdAt,
		Payload:     payload,
		Attachments: attInfos,
		Signature:   sigHex,
	}

	if _, err := s.writeAtomicJSONWithCommitState(filepath.Join(tmpDir, "message.json"), msg); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := s.syncDirLocked(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := s.syncDirLocked(s.stagingDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	if err := os.Rename(tmpDir, msgDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		if _, statErr := os.Stat(msgDir); statErr == nil {
			if existing, rErr := readMessageJSON(msgDir); rErr == nil && existing.ID != msgID {
				return nil, ErrStorageCollision
			}
			return nil, ErrAlreadyPublished
		}
		return nil, err
	}
	if err := s.syncDirLocked(s.outboxDir); err != nil {
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

	now := time.Now().UTC()
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
		if dirName != storageDirKey(msg.ID) {
			continue
		}
		if seenIDs[msg.ID] {
			continue
		}

		// Supplementary sanity check: verify all declared attachments exist as regular files with matching size.
		complete := true
		for _, att := range msg.Attachments {
			cleanAtt, err := SanitizeFilename(att.Name)
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
	cleanID, err := SanitizeID(id)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, msg, err := s.resolveOutboxDirLocked(cleanID)
	if err != nil {
		return nil, err
	}
	s.inFlightUntil[cleanID] = time.Now().UTC().Add(OutboxLeaseDuration)
	return msg, nil
}

// GetOutboxAttachmentPath returns path to an attachment file in outbox snapshot.
func (s *Storage) GetOutboxAttachmentPath(id, filename string) (string, error) {
	cleanID, err := SanitizeID(id)
	if err != nil {
		return "", err
	}
	cleanFile, err := SanitizeFilename(filename)
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
// (used only when unsigned mode is explicitly selected).
func (s *Storage) AcknowledgeMessages(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	removedAny := false
	for _, rawID := range ids {
		cleanID, err := SanitizeID(rawID)
		if err != nil {
			continue
		}
		msgDir, _, resolveErr := s.resolveOutboxDirLocked(cleanID)
		delete(s.inFlightUntil, cleanID)
		if resolveErr == nil && msgDir != "" {
			if err := os.RemoveAll(msgDir); err != nil {
				return err
			}
			removedAny = true
		}
	}
	if removedAny {
		if err := s.syncDirLocked(s.outboxDir); err != nil {
			return err
		}
	}
	return nil
}

// AcknowledgeMessagesVerified removes acknowledged messages from outbox (Rule 6),
// strictly verifying cryptographic ACK receipts against the configured peer public key (fail-closed).
func (s *Storage) AcknowledgeMessagesVerified(ids []string, receipts map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.signingConfigured {
		return ErrSigningNotConfigured
	}

	removedAny := false
	for _, rawID := range ids {
		cleanID, err := SanitizeID(rawID)
		if err != nil {
			continue
		}
		msgDir, outMsg, resolveErr := s.resolveOutboxDirLocked(cleanID)
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
		if err := VerifyAckReceipt(s.peerPubKey, s.peerIdentity, cleanID, outMsg.Signature, receiptHex); err != nil {
			return fmt.Errorf("ACK receipt verification failed for %s: %w", cleanID, err)
		}

		delete(s.inFlightUntil, cleanID)
		if msgDir != "" {
			if err := os.RemoveAll(msgDir); err != nil {
				return err
			}
			removedAny = true
		}
	}
	if removedAny {
		if err := s.syncDirLocked(s.outboxDir); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Inbox & Acceptance Management (Rules 3, 4, 5)
// -----------------------------------------------------------------------------

// AcceptanceStatus represents the durable acceptance status, timestamp, and optional signed receipt for a message ID.
type AcceptanceStatus struct {
	Accepted   bool       `json:"accepted"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	AckReceipt string     `json:"ack_receipt,omitempty"`
}

// IsAccepted returns true if the message ID has already been durably accepted.
func (s *Storage) IsAccepted(id string) bool {
	cleanID, err := SanitizeID(id)
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.acceptedRecords[cleanID]
	return ok
}

// GetAcceptedRecord returns the full AcceptedRecord for a confirmed message ID if present.
func (s *Storage) GetAcceptedRecord(id string) (AcceptedRecord, bool) {
	cleanID, err := SanitizeID(id)
	if err != nil {
		return AcceptedRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.acceptedRecords[cleanID]
	return rec, ok
}

// GetAcceptance checks a bounded batch of message IDs and returns an explicit AcceptanceStatus
// for every requested ID. If any requested ID has an unresolved durability flush (`pendingCommits`),
// GetAcceptance attempts to finalize the flush first and returns a storage error if synchronization still fails.
func (s *Storage) GetAcceptance(ids []string) (map[string]AcceptanceStatus, error) {
	if len(ids) > MaxBatchIDs {
		return nil, ErrTooManyIDs
	}

	cleanIDs := make([]string, 0, len(ids))
	for _, rawID := range ids {
		cleanID, err := SanitizeID(rawID)
		if err != nil {
			return nil, err
		}
		cleanIDs = append(cleanIDs, cleanID)
	}

	s.mu.RLock()
	hasPending := false
	for _, id := range cleanIDs {
		if _, ok := s.pendingCommits[id]; ok {
			hasPending = true
			break
		}
	}
	if !hasPending {
		results := s.buildAcceptanceMapLocked(cleanIDs)
		s.mu.RUnlock()
		return results, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range cleanIDs {
		if _, ok := s.pendingCommits[id]; ok {
			if _, err := s.finalizePendingCommitLocked(id); err != nil {
				return nil, err
			}
		}
	}
	return s.buildAcceptanceMapLocked(cleanIDs), nil
}

func (s *Storage) buildAcceptanceMapLocked(cleanIDs []string) map[string]AcceptanceStatus {
	results := make(map[string]AcceptanceStatus, len(cleanIDs))
	for _, id := range cleanIDs {
		if _, exists := results[id]; exists {
			continue
		}
		rec, ok := s.acceptedRecords[id]
		if !ok {
			results[id] = AcceptanceStatus{Accepted: false}
			continue
		}
		receipt := rec.AckReceipt
		if receipt == "" {
			if _, m, err := s.resolveInboxDirLocked(id); err == nil && m != nil && m.AckReceipt != "" {
				receipt = m.AckReceipt
			}
		}
		ts := rec.AcceptedAt.UTC()
		results[id] = AcceptanceStatus{
			Accepted:   true,
			AcceptedAt: &ts,
			AckReceipt: receipt,
		}
	}
	return results
}

// ListAccepted returns all confirmed accepted message IDs.
func (s *Storage) ListAccepted() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ids []string
	for id := range s.acceptedRecords {
		ids = append(ids, id)
	}
	return ids
}

// ListAcceptedReceipts returns a map of confirmed accepted message ID -> cryptographic ACK receipt.
func (s *Storage) ListAcceptedReceipts() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	receipts := make(map[string]string, len(s.acceptedRecords))
	for id, rec := range s.acceptedRecords {
		if rec.AckReceipt != "" {
			receipts[id] = rec.AckReceipt
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

// ListAcceptedRecords returns a copy of all confirmed AcceptedRecord entries.
func (s *Storage) ListAcceptedRecords() map[string]AcceptedRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]AcceptedRecord, len(s.acceptedRecords))
	for id, rec := range s.acceptedRecords {
		out[id] = rec
	}
	return out
}

// ListInbox returns all confirmed accepted messages currently stored in inbox.
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
		if dirName != storageDirKey(msg.ID) {
			continue
		}
		if _, ok := s.acceptedRecords[msg.ID]; !ok || seenIDs[msg.ID] {
			continue
		}
		seenIDs[msg.ID] = true
		msgs = append(msgs, msg)
	}

	return msgs, nil
}

// GetInboxMessage retrieves an accepted message from inbox.
func (s *Storage) GetInboxMessage(id string) (*Message, error) {
	cleanID, err := SanitizeID(id)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.acceptedRecords[cleanID]; !ok {
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
	cleanID, err := SanitizeID(id)
	if err != nil {
		return "", err
	}
	cleanFile, err := SanitizeFilename(filename)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.acceptedRecords[cleanID]; !ok {
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

// AcceptMessage performs all-or-nothing acceptance of a PUT message (Rules 3 & 4) without requiring signatures
// (used only when unsigned mode is explicitly chosen).
func (s *Storage) AcceptMessage(id string, payload any, attachments []AttachmentReader) (*Message, error) {
	return s.acceptMessageInternal(id, payload, attachments, "", false)
}

// AcceptSignedMessage performs all-or-nothing acceptance of a PUT message (Rules 3 & 4),
// strictly requiring configured signing keys and verifying the sender's Ed25519 signature (fail-closed).
func (s *Storage) AcceptSignedMessage(id string, payload any, attachments []AttachmentReader, sigHex string) (*Message, error) {
	return s.acceptMessageInternal(id, payload, attachments, sigHex, true)
}

func (s *Storage) hashIncomingCandidateLocked(cleanID string, payload any, attachments []AttachmentReader) ([]AttachmentInfo, string, error) {
	if len(attachments) > MaxAttachmentsPerMessage {
		return nil, "", ErrTooManyAttachments
	}
	var attInfos []AttachmentInfo
	seenNames := make(map[string]bool)
	for _, att := range attachments {
		cleanName, err := SanitizeFilename(att.Name)
		if err != nil {
			return nil, "", err
		}
		cleanMedia, err := ValidateMediaType(att.MediaType)
		if err != nil {
			return nil, "", err
		}
		if seenNames[cleanName] {
			return nil, "", fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
		}
		seenNames[cleanName] = true
		if att.Reader == nil {
			return nil, "", fmt.Errorf("nil reader for attachment %s", cleanName)
		}

		hasher := sha256.New()
		limitReader := io.LimitReader(att.Reader, s.maxUploadSize+1)
		n, err := io.Copy(hasher, limitReader)
		if err != nil {
			return nil, "", err
		}
		if n > s.maxUploadSize {
			return nil, "", ErrFileTooLarge
		}
		attInfos = append(attInfos, AttachmentInfo{
			Name:      cleanName,
			Size:      n,
			SHA256:    hex.EncodeToString(hasher.Sum(nil)),
			MediaType: cleanMedia,
		})
	}
	incomingDigest, err := s.computeIncomingDigestLocked(cleanID, payload, attInfos)
	if err != nil {
		return nil, "", err
	}
	return attInfos, incomingDigest, nil
}

func (s *Storage) verifyDuplicateCandidateLocked(
	cleanID string,
	payload any,
	attachments []AttachmentReader,
	sigHex string,
	requireSignature bool,
	expectedDigest string,
	expectedReceipt string,
) ([]AttachmentInfo, error) {
	attInfos, incomingDigest, err := s.hashIncomingCandidateLocked(cleanID, payload, attachments)
	if err != nil {
		return nil, err
	}

	if (requireSignature || strings.TrimSpace(sigHex) != "") && s.signingConfigured {
		if err := VerifyPutMessage(s.peerPubKey, s.peerIdentity, s.localIdentity, cleanID, payload, attInfos, sigHex); err != nil {
			return nil, err
		}
	}

	if expectedDigest == "" || !strings.EqualFold(incomingDigest, expectedDigest) {
		return nil, ErrConflictingDuplicate
	}

	if (requireSignature || strings.TrimSpace(sigHex) != "") && s.signingConfigured && expectedReceipt != "" {
		if err := VerifyAckReceipt(s.ownPubKey, s.localIdentity, cleanID, strings.TrimSpace(sigHex), expectedReceipt); err != nil {
			return nil, ErrInvalidSignature
		}
	}

	return attInfos, nil
}

func (s *Storage) acceptMessageInternal(id string, payload any, attachments []AttachmentReader, sigHex string, requireSignature bool) (*Message, error) {
	if len(attachments) > MaxAttachmentsPerMessage {
		return nil, ErrTooManyAttachments
	}
	if payload == nil {
		payload = map[string]any{}
	}

	cleanID, err := SanitizeID(id)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if requireSignature && !s.signingConfigured {
		return nil, ErrSigningNotConfigured
	}

	dirKey := storageDirKey(cleanID)
	committingPath := filepath.Join(s.committingDir, dirKey)
	targetDir := filepath.Join(s.inboxDir, dirKey)

	// 0. Unresolved durability check: if accepted.json was previously renamed on disk for this ID
	//    but directory synchronization or inbox exposure failed, verify full content + signature match
	//    and retry finalization.
	if pendingMsg, isPending := s.pendingCommits[cleanID]; isPending {
		expectedDigest := pendingMsg.Digest
		if expectedDigest == "" {
			expectedDigest, _ = s.computeIncomingDigestLocked(cleanID, pendingMsg.Payload, pendingMsg.Attachments)
		}
		if _, err := s.verifyDuplicateCandidateLocked(cleanID, payload, attachments, sigHex, requireSignature, expectedDigest, pendingMsg.AckReceipt); err != nil {
			return nil, err
		}
		return s.finalizePendingCommitLocked(cleanID)
	}

	// 1. Confirmed duplicate check: applies identically whether inbox/m-<sha256(id)> still exists on disk
	//    or has already been archived/deleted by a downstream consumer.
	if rec, isAccepted := s.acceptedRecords[cleanID]; isAccepted {
		_, existing, resolveErr := s.resolveInboxDirLocked(cleanID)
		expectedDigest := rec.Digest
		if expectedDigest == "" && resolveErr == nil && existing != nil {
			expectedDigest, _ = s.computeIncomingDigestLocked(cleanID, existing.Payload, existing.Attachments)
			if expectedDigest != "" {
				rec.Digest = expectedDigest
				s.acceptedRecords[cleanID] = rec
			}
		}
		attInfos, err := s.verifyDuplicateCandidateLocked(cleanID, payload, attachments, sigHex, requireSignature, expectedDigest, rec.AckReceipt)
		if err != nil {
			return nil, err
		}

		origAcceptedAt := rec.AcceptedAt.UTC()
		if resolveErr == nil && existing != nil {
			if existing.AcceptedAt == nil {
				existing.AcceptedAt = &origAcceptedAt
			}
			if existing.AckReceipt == "" {
				existing.AckReceipt = rec.AckReceipt
			}
			return existing, nil
		}

		return &Message{
			ID:          cleanID,
			AcceptedAt:  &origAcceptedAt,
			Payload:     payload,
			Attachments: attInfos,
			Signature:   strings.TrimSpace(sigHex),
			AckReceipt:  rec.AckReceipt,
			Digest:      expectedDigest,
		}, nil
	}

	// 2. Pre-check destination directories before staging. NEVER call RemoveAll on an existing inbox directory.
	if _, statErr := os.Stat(targetDir); statErr == nil {
		existing, readErr := readMessageJSON(targetDir)
		if readErr != nil || existing.ID != cleanID {
			return nil, ErrStorageCollision
		}
		existingDigest := existing.Digest
		if existingDigest == "" {
			existingDigest, err = s.computeIncomingDigestLocked(existing.ID, existing.Payload, existing.Attachments)
			if err != nil {
				return nil, err
			}
			existing.Digest = existingDigest
		}
		if _, err := s.verifyDuplicateCandidateLocked(cleanID, payload, attachments, sigHex, requireSignature, existingDigest, existing.AckReceipt); err != nil {
			return nil, err
		}
		acceptedAt := time.Now().UTC()
		if existing.AcceptedAt != nil && !existing.AcceptedAt.IsZero() {
			acceptedAt = existing.AcceptedAt.UTC()
		}
		existing.AcceptedAt = &acceptedAt

		candidateRec := AcceptedRecord{
			AcceptedAt: acceptedAt,
			AckReceipt: existing.AckReceipt,
			Digest:     existingDigest,
		}
		renamedOnDisk, pErr := s.persistAcceptedRecordsWithCandidateLocked(cleanID, &candidateRec)
		if pErr != nil {
			if renamedOnDisk {
				s.pendingCommits[cleanID] = existing
			}
			return nil, fmt.Errorf("persisting accepted ID: %w", pErr)
		}
		s.pendingCommits[cleanID] = existing
		return s.finalizePendingCommitLocked(cleanID)
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	if _, statErr := os.Stat(committingPath); statErr == nil {
		existing, readErr := readMessageJSON(committingPath)
		if readErr == nil && existing.ID != cleanID {
			return nil, ErrStorageCollision
		}
		if err := os.RemoveAll(committingPath); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	// 3. Stage files and message.json inside dedicated .staging/ namespace: all-or-nothing
	tmpDir := filepath.Join(s.stagingDir, fmt.Sprintf("inbox-%s-%d", dirKey, time.Now().UTC().UnixNano()))
	tmpAttachmentsDir := filepath.Join(tmpDir, "attachments")
	if err := os.MkdirAll(tmpAttachmentsDir, 0700); err != nil {
		return nil, err
	}

	var attInfos []AttachmentInfo
	seenNames := make(map[string]bool)
	for _, att := range attachments {
		cleanName, err := SanitizeFilename(att.Name)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		cleanMedia, err := ValidateMediaType(att.MediaType)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if seenNames[cleanName] {
			_ = os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAttachment, cleanName)
		}
		seenNames[cleanName] = true
		if att.Reader == nil {
			_ = os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("nil reader for attachment %s", cleanName)
		}

		dstPath := filepath.Join(tmpAttachmentsDir, cleanName)
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
			Name:      cleanName,
			Size:      n,
			SHA256:    hex.EncodeToString(hasher.Sum(nil)),
			MediaType: cleanMedia,
		})
	}
	if err := s.syncDirLocked(tmpAttachmentsDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	if (requireSignature || strings.TrimSpace(sigHex) != "") && s.signingConfigured {
		if err := VerifyPutMessage(s.peerPubKey, s.peerIdentity, s.localIdentity, cleanID, payload, attInfos, sigHex); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
	}

	incomingDigest, err := s.computeIncomingDigestLocked(cleanID, payload, attInfos)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	ackReceipt := ""
	if s.signingConfigured {
		ackReceipt, err = SignAckReceipt(s.ownPrivKey, s.localIdentity, cleanID, sigHex)
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
	}

	acceptedAt := time.Now().UTC()
	msg := &Message{
		ID:          cleanID,
		AcceptedAt:  &acceptedAt,
		Payload:     payload,
		Attachments: attInfos,
		Signature:   strings.TrimSpace(sigHex),
		AckReceipt:  ackReceipt,
		Digest:      incomingDigest,
	}

	if _, err := s.writeAtomicJSONWithCommitState(filepath.Join(tmpDir, "message.json"), msg); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := s.syncDirLocked(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := s.syncDirLocked(s.stagingDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	// 4. Move staged message to .committing/m-<sha256(id)> (invisible to external inbox/ consumers).
	if err := os.Rename(tmpDir, committingPath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := s.syncDirLocked(s.committingDir); err != nil {
		_ = os.RemoveAll(committingPath)
		return nil, err
	}

	// 5. Persist consolidated accepted.json (id -> {accepted_at, ack_receipt, digest}) and synchronize dataDir BEFORE exposing inbox/.
	candidateRec := AcceptedRecord{
		AcceptedAt: acceptedAt,
		AckReceipt: ackReceipt,
		Digest:     incomingDigest,
	}
	renamedOnDisk, err := s.persistAcceptedRecordsWithCandidateLocked(cleanID, &candidateRec)
	if err != nil {
		if !renamedOnDisk {
			_ = os.RemoveAll(committingPath)
			_ = s.syncDirLocked(s.committingDir)
			return nil, fmt.Errorf("persisting accepted ID: %w", err)
		}
		s.pendingCommits[cleanID] = msg
		return nil, fmt.Errorf("syncing accepted ID index: %w", err)
	}

	// 6. Finalize inbox exposure + directory synchronization before confirming acceptedRecords[cleanID].
	s.pendingCommits[cleanID] = msg
	return s.finalizePendingCommitLocked(cleanID)
}

func (s *Storage) finalizePendingCommitLocked(cleanID string) (*Message, error) {
	pendingMsg, ok := s.pendingCommits[cleanID]
	if !ok {
		return nil, ErrNotFound
	}

	if err := s.syncDirLocked(s.dataDir); err != nil {
		return nil, fmt.Errorf("syncing accepted ID index: %w", err)
	}

	dirKey := storageDirKey(cleanID)
	committingPath := filepath.Join(s.committingDir, dirKey)
	targetDir := filepath.Join(s.inboxDir, dirKey)
	if _, statErr := os.Stat(committingPath); statErr == nil {
		if _, dstErr := os.Stat(targetDir); os.IsNotExist(dstErr) {
			if err := os.Rename(committingPath, targetDir); err != nil {
				return nil, fmt.Errorf("moving committed message into inbox: %w", err)
			}
		} else if dstErr != nil {
			return nil, dstErr
		}
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}

	if err := s.syncDirLocked(s.inboxDir); err != nil {
		return nil, fmt.Errorf("syncing inbox directory: %w", err)
	}
	_ = s.syncDirLocked(s.committingDir)

	acceptedAt := time.Now().UTC()
	if pendingMsg.AcceptedAt != nil && !pendingMsg.AcceptedAt.IsZero() {
		acceptedAt = pendingMsg.AcceptedAt.UTC()
	}
	pendingMsg.AcceptedAt = &acceptedAt

	digest := pendingMsg.Digest
	if digest == "" {
		digest, _ = s.computeIncomingDigestLocked(cleanID, pendingMsg.Payload, pendingMsg.Attachments)
	}

	s.acceptedRecords[cleanID] = AcceptedRecord{
		AcceptedAt: acceptedAt,
		AckReceipt: pendingMsg.AckReceipt,
		Digest:     digest,
	}
	delete(s.pendingCommits, cleanID)
	return pendingMsg, nil
}

// -----------------------------------------------------------------------------
// Persistence & Recovery Helpers
// -----------------------------------------------------------------------------

func (s *Storage) loadAcceptedIDs() error {
	_ = os.RemoveAll(s.stagingDir)
	if err := os.MkdirAll(s.stagingDir, 0700); err != nil {
		return err
	}

	needsPersist := false
	loadedIndexFile := false

	data, err := os.ReadFile(s.acceptedFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		loadedIndexFile = true
		var mapFormat map[string]AcceptedRecord
		if err := json.Unmarshal(data, &mapFormat); err != nil || mapFormat == nil {
			if err != nil {
				return err
			}
			return errors.New("invalid accepted.json format")
		}
		for id, rec := range mapFormat {
			clean, err := SanitizeID(id)
			if err != nil || clean != id {
				return ErrInvalidID
			}
			if rec.AcceptedAt.IsZero() {
				rec.AcceptedAt = time.Now().UTC()
			} else {
				rec.AcceptedAt = rec.AcceptedAt.UTC()
			}
			s.acceptedRecords[clean] = rec
		}
	}

	if loadedIndexFile {
		if err := s.syncDirLocked(s.dataDir); err != nil {
			return err
		}
	}

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
			if readErr == nil && entry.Name() == storageDirKey(msg.ID) {
				if rec, ok := s.acceptedRecords[msg.ID]; ok {
					updated := false
					if msg.AckReceipt != "" && rec.AckReceipt == "" {
						rec.AckReceipt = msg.AckReceipt
						updated = true
					}
					if msg.Digest != "" && rec.Digest == "" {
						rec.Digest = msg.Digest
						updated = true
					}
					if updated {
						s.acceptedRecords[msg.ID] = rec
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
					continue
				}
			}
			_ = os.RemoveAll(commPath)
			commChanged = true
		}
		if inboxChanged {
			if err := s.syncDirLocked(s.inboxDir); err != nil {
				return err
			}
		}
		if commChanged {
			if err := s.syncDirLocked(s.committingDir); err != nil {
				return err
			}
		}
	}

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
			if dirName != storageDirKey(msg.ID) {
				continue
			}
			rec, exists := s.acceptedRecords[msg.ID]
			if !exists {
				acceptedAt := time.Now().UTC()
				if msg.AcceptedAt != nil && !msg.AcceptedAt.IsZero() {
					acceptedAt = msg.AcceptedAt.UTC()
				}
				rec = AcceptedRecord{
					AcceptedAt: acceptedAt,
					AckReceipt: msg.AckReceipt,
					Digest:     msg.Digest,
				}
				s.acceptedRecords[msg.ID] = rec
				needsPersist = true
				continue
			}
			updated := false
			if msg.AckReceipt != "" && rec.AckReceipt == "" {
				rec.AckReceipt = msg.AckReceipt
				updated = true
			}
			if msg.Digest != "" && rec.Digest == "" {
				rec.Digest = msg.Digest
				updated = true
			}
			if updated {
				s.acceptedRecords[msg.ID] = rec
				needsPersist = true
			}
		}
	}

	if needsPersist {
		if _, err := s.persistAcceptedRecordsWithCandidateLocked("", nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Storage) persistAcceptedRecordsWithCandidateLocked(candidateID string, candidate *AcceptedRecord) (bool, error) {
	consolidated := make(map[string]AcceptedRecord, len(s.acceptedRecords)+len(s.pendingCommits)+1)
	for id, rec := range s.acceptedRecords {
		rec.AcceptedAt = rec.AcceptedAt.UTC()
		consolidated[id] = rec
	}
	for id, pending := range s.pendingCommits {
		acceptedAt := time.Now().UTC()
		if pending.AcceptedAt != nil && !pending.AcceptedAt.IsZero() {
			acceptedAt = pending.AcceptedAt.UTC()
		}
		consolidated[id] = AcceptedRecord{
			AcceptedAt: acceptedAt,
			AckReceipt: pending.AckReceipt,
			Digest:     pending.Digest,
		}
	}
	if candidateID != "" && candidate != nil {
		c := *candidate
		c.AcceptedAt = c.AcceptedAt.UTC()
		consolidated[candidateID] = c
	}
	return s.writeAtomicJSONWithCommitState(s.acceptedFile, consolidated)
}

func (s *Storage) writeAtomicJSONWithCommitState(targetPath string, v any) (bool, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return false, err
	}

	nameSum := sha256.Sum256([]byte(filepath.Base(targetPath)))
	tmpPath := filepath.Join(s.stagingDir, fmt.Sprintf("json-%s-%d", hex.EncodeToString(nameSum[:8]), time.Now().UTC().UnixNano()))
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
	if err := s.syncDirLocked(s.stagingDir); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	if err := s.syncDirLocked(filepath.Dir(targetPath)); err != nil {
		return true, err
	}
	return true, nil
}
