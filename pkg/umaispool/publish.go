package umaispool

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
	"time"
)

var (
	ErrMissingDataDir = errors.New("spool data directory is required")
)

// PublishRequest configures a stateless, producer-owned outbox publication into <DataDir>/outbox/.
//
// Unlike Storage methods, Publish never opens or mutates server-owned state (.staging/, .committing/,
// accepted.json, or inbox/). All temporary files are prepared inside <DataDir>/prepare/ and exposed
// to the spool server only via a final atomic directory rename into <DataDir>/outbox/m-<sha256(id)>/.
type PublishRequest struct {
	DataDir           string
	ID                string // Optional; auto-generated via GenerateMessageID() when empty
	Payload           any
	Attachments       []AttachmentReader
	MaxAttachmentSize int64          // Defaults to 100 MiB when <= 0
	Signing           *SigningConfig // Required unless AllowUnsigned is explicitly true
	AllowUnsigned     bool
}

// Publish atomically stages and publishes an immutable outgoing message into <req.DataDir>/outbox/.
//
// Guarantees:
//   - Fails closed with ErrSigningNotConfigured unless req.Signing is valid or req.AllowUnsigned is true.
//   - Stages all files exclusively inside <req.DataDir>/prepare/ (untouched by server startup recovery).
//   - Syncs every attachment file, attachments/, message.json, the staged directory, prepare/, and outbox/.
//   - Never overwrites or modifies an already-published Message ID (returns ErrAlreadyPublished).
func Publish(req PublishRequest) (*Message, error) {
	if strings.TrimSpace(req.DataDir) == "" {
		return nil, ErrMissingDataDir
	}
	if len(req.Attachments) > MaxAttachmentsPerMessage {
		return nil, ErrTooManyAttachments
	}

	var localIdentity, peerIdentity string
	var privKey ed25519.PrivateKey
	signMessage := false

	if req.Signing != nil {
		localTrim := strings.TrimSpace(req.Signing.LocalIdentity)
		peerTrim := strings.TrimSpace(req.Signing.PeerIdentity)
		if localTrim == "" || peerTrim == "" {
			return nil, ErrMissingIdentity
		}
		if localTrim != req.Signing.LocalIdentity || peerTrim != req.Signing.PeerIdentity || localTrim == peerTrim {
			return nil, ErrInvalidIdentity
		}
		if len(req.Signing.PrivateKey) != ed25519.PrivateKeySize {
			return nil, ErrSigningNotConfigured
		}
		if len(req.Signing.PeerPublicKey) != 0 && len(req.Signing.PeerPublicKey) != ed25519.PublicKeySize {
			return nil, ErrSigningNotConfigured
		}
		localIdentity = localTrim
		peerIdentity = peerTrim
		privKey = req.Signing.PrivateKey
		signMessage = true
	} else if !req.AllowUnsigned {
		return nil, ErrSigningNotConfigured
	}

	maxSize := req.MaxAttachmentSize
	if maxSize <= 0 {
		maxSize = DefaultMaxUploadSize
	}

	payload := req.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	if _, err := json.Marshal(payload); err != nil {
		return nil, fmt.Errorf("marshaling payload: %w", err)
	}

	var msgID string
	if strings.TrimSpace(req.ID) == "" {
		msgID = GenerateMessageID()
	} else {
		cleanID, err := SanitizeID(req.ID)
		if err != nil || cleanID != req.ID {
			return nil, ErrInvalidID
		}
		msgID = cleanID
	}

	absDataDir, err := filepath.Abs(req.DataDir)
	if err != nil {
		return nil, fmt.Errorf("resolving data directory: %w", err)
	}
	prepareDir := filepath.Join(absDataDir, "prepare")
	outboxDir := filepath.Join(absDataDir, "outbox")

	for _, dir := range []string{absDataDir, prepareDir, outboxDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	dirKey := storageDirKey(msgID)
	msgDir := filepath.Join(outboxDir, dirKey)
	if _, err := os.Stat(msgDir); err == nil {
		if existing, rErr := readMessageJSON(msgDir); rErr == nil && existing.ID != msgID {
			return nil, ErrStorageCollision
		}
		return nil, ErrAlreadyPublished
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("generating staging nonce: %w", err)
	}
	tmpDir := filepath.Join(prepareDir, fmt.Sprintf("pub-%s-%s", dirKey, hex.EncodeToString(randBytes)))
	attachmentsDir := filepath.Join(tmpDir, "attachments")
	if err := os.Mkdir(tmpDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(attachmentsDir, 0700); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	var attInfos []AttachmentInfo
	seenNames := make(map[string]bool)

	for _, att := range req.Attachments {
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
		limitReader := io.LimitReader(att.Reader, maxSize+1)
		n, err := io.Copy(writer, limitReader)
		if err != nil {
			_ = dstFile.Close()
			_ = os.RemoveAll(tmpDir)
			return nil, err
		}
		if n > maxSize {
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

	if err := SyncDir(attachmentsDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	sigHex := ""
	if signMessage {
		sigHex, err = SignPutMessage(privKey, localIdentity, peerIdentity, msgID, payload, attInfos)
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

	msgJSONBytes, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	msgFilePath := filepath.Join(tmpDir, "message.json")
	msgFile, err := os.OpenFile(msgFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if _, err := msgFile.Write(msgJSONBytes); err != nil {
		_ = msgFile.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := msgFile.Sync(); err != nil {
		_ = msgFile.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := msgFile.Close(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}

	if err := SyncDir(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := SyncDir(prepareDir); err != nil {
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

	if err := SyncDir(outboxDir); err != nil {
		return nil, err
	}

	return msg, nil
}
