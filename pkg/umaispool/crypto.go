// Package umaispool provides a reusable, zero-dependency file-spool storage engine,
// Ed25519 canonical message/receipt signing, and an authenticated HTTP handler
// implementing the backend side of the UMAI 0.1 browser-mediated protocol.
package umaispool

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	// MaxMediaTypeLength bounds optional sender-declared attachment media types ("type/subtype").
	MaxMediaTypeLength = 127
)

var (
	ErrInvalidSignature     = errors.New("invalid or missing cryptographic signature")
	ErrInvalidReceipt       = errors.New("invalid or missing cryptographic ACK receipt")
	ErrMissingIdentity      = errors.New("missing sender or receiver identity")
	ErrInvalidIdentity      = errors.New("local identity and peer identity must be distinct and trimmed")
	ErrSigningNotConfigured = errors.New("cryptographic signing keys and identities are not configured")
	ErrInvalidMediaType     = errors.New("invalid attachment media_type: expected lowercase ASCII type/subtype without parameters")
)

// ValidateMediaType validates and normalizes an optional parameterless MIME media type ("type/subtype").
// Empty or whitespace-only input normalizes to "" (absent). Non-empty values are trimmed, lowercased,
// bounded to MaxMediaTypeLength (127 ASCII bytes), rejected if they contain parameters (';') or multiple
// slashes, and validated against RFC 6838 restricted token characters.
func ValidateMediaType(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) > MaxMediaTypeLength {
		return "", ErrInvalidMediaType
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c <= 32 || c > 126 {
			return "", ErrInvalidMediaType
		}
	}
	normalized := strings.ToLower(trimmed)
	slashIdx := strings.IndexByte(normalized, '/')
	if slashIdx <= 0 || slashIdx == len(normalized)-1 {
		return "", ErrInvalidMediaType
	}
	typePart := normalized[:slashIdx]
	subPart := normalized[slashIdx+1:]
	if !isValidMediaToken(typePart) || !isValidMediaToken(subPart) {
		return "", ErrInvalidMediaType
	}
	return normalized, nil
}

func isValidMediaToken(part string) bool {
	if len(part) == 0 || len(part) > MaxMediaTypeLength {
		return false
	}
	for i := 0; i < len(part); i++ {
		c := part[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return false
			}
			continue
		}
		if isAlphaNum {
			continue
		}
		switch c {
		case '!', '#', '$', '&', '-', '^', '_', '.', '+':
			// Allowed RFC 6838 restricted-name characters
		default:
			return false
		}
	}
	return true
}

// ParsePrivateKey parses a hex-encoded Ed25519 private key (32-byte seed or 64-byte expanded key).
// It never falls back to default keys.
func ParsePrivateKey(privHex string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privTrimmed := strings.TrimSpace(privHex)
	if privTrimmed == "" {
		return nil, nil, ErrSigningNotConfigured
	}
	rawPriv, err := hex.DecodeString(privTrimmed)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding signing private key hex: %w", err)
	}
	switch len(rawPriv) {
	case ed25519.SeedSize:
		ownPriv := ed25519.NewKeyFromSeed(rawPriv)
		return ownPriv.Public().(ed25519.PublicKey), ownPriv, nil
	case ed25519.PrivateKeySize:
		ownPriv := ed25519.PrivateKey(rawPriv)
		return ownPriv.Public().(ed25519.PublicKey), ownPriv, nil
	default:
		return nil, nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(rawPriv))
	}
}

// ParseSigningKeys parses hex-encoded Ed25519 private (32-byte seed or 64-byte key)
// and 32-byte peer public keys. Unlike demo utilities, it never falls back to default keys.
func ParseSigningKeys(privHex, peerPubHex string) (ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, error) {
	peerTrimmed := strings.TrimSpace(peerPubHex)
	if strings.TrimSpace(privHex) == "" || peerTrimmed == "" {
		return nil, nil, nil, ErrSigningNotConfigured
	}
	ownPub, ownPriv, err := ParsePrivateKey(privHex)
	if err != nil {
		return nil, nil, nil, err
	}

	rawPeer, err := hex.DecodeString(peerTrimmed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding peer public key hex: %w", err)
	}
	if len(rawPeer) != ed25519.PublicKeySize {
		return nil, nil, nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(rawPeer))
	}

	return ownPub, ownPriv, ed25519.PublicKey(rawPeer), nil
}

// CanonicalPutDigest computes the unambiguous, length-prefixed canonical SHA-256 digest of a UMAI PUT message:
//
//	UMAI-PUT-V1\n
//	sender:<len>:<sender_identity>\n
//	receiver:<len>:<receiver_identity>\n
//	id:<len>:<id>\n
//	payload:<payload_canonical_sha256>\n
//	att_count:<count>\n
//	att:<name_len>:<att1_name>:<att1_size>:<att1_sha256>:<media_type_len>:<att1_media_type>\n...
//
// Binding both sender and intended receiver prevents cross-channel or multi-peer misdirection,
// length-prefixing variable-length strings guarantees injectivity (zero delimiter collision ambiguity),
// normalizing optional media_type ensures consistent treatment before signing and verification,
// and sorting attachments by sanitized name ensures ordering differences never break verification.
func CanonicalPutDigest(senderIdentity string, receiverIdentity string, id string, payload any, attachments []AttachmentInfo) ([32]byte, error) {
	if strings.TrimSpace(senderIdentity) == "" || strings.TrimSpace(receiverIdentity) == "" {
		return [32]byte{}, ErrMissingIdentity
	}
	if payload == nil {
		payload = map[string]any{}
	}
	// Normalize payload through JSON round-trip so map types and json.Unmarshal outputs produce identical JSON
	var normalized any
	rawBytes, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, err
	}
	if len(rawBytes) > 0 && string(rawBytes) != "null" {
		dec := json.NewDecoder(bytes.NewReader(rawBytes))
		dec.UseNumber()
		_ = dec.Decode(&normalized)
	} else {
		normalized = map[string]any{}
	}
	canonicalPayload, err := json.Marshal(normalized)
	if err != nil {
		return [32]byte{}, err
	}
	payloadHash := sha256.Sum256(canonicalPayload)

	sortedAtts := make([]AttachmentInfo, len(attachments))
	for i, a := range attachments {
		cleanMedia, err := ValidateMediaType(a.MediaType)
		if err != nil {
			return [32]byte{}, err
		}
		a.MediaType = cleanMedia
		sortedAtts[i] = a
	}
	sort.Slice(sortedAtts, func(i, j int) bool {
		return sortedAtts[i].Name < sortedAtts[j].Name
	})

	var sb strings.Builder
	sb.WriteString("UMAI-PUT-V1\n")
	sb.WriteString(fmt.Sprintf("sender:%d:%s\n", len(senderIdentity), senderIdentity))
	sb.WriteString(fmt.Sprintf("receiver:%d:%s\n", len(receiverIdentity), receiverIdentity))
	sb.WriteString(fmt.Sprintf("id:%d:%s\n", len(id), id))
	sb.WriteString(fmt.Sprintf("payload:%s\n", hex.EncodeToString(payloadHash[:])))
	sb.WriteString(fmt.Sprintf("att_count:%d\n", len(sortedAtts)))
	for _, a := range sortedAtts {
		sb.WriteString(fmt.Sprintf("att:%d:%s:%d:%s:%d:%s\n",
			len(a.Name), a.Name,
			a.Size, a.SHA256,
			len(a.MediaType), a.MediaType,
		))
	}

	return sha256.Sum256([]byte(sb.String())), nil
}

// SignPutMessage signs a message's canonical PUT digest (binding sender and intended receiver)
// with the sender's Ed25519 private key.
func SignPutMessage(priv ed25519.PrivateKey, senderIdentity string, receiverIdentity string, id string, payload any, attachments []AttachmentInfo) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", ErrSigningNotConfigured
	}
	digest, err := CanonicalPutDigest(senderIdentity, receiverIdentity, id, payload, attachments)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, digest[:])
	return hex.EncodeToString(sig), nil
}

// VerifyPutMessage verifies a message's canonical PUT digest against the sender's Ed25519 public key
// and expected sender/receiver identities.
func VerifyPutMessage(pub ed25519.PublicKey, expectedSenderIdentity string, expectedReceiverIdentity string, id string, payload any, attachments []AttachmentInfo, sigHex string) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrSigningNotConfigured
	}
	if strings.TrimSpace(expectedSenderIdentity) == "" || strings.TrimSpace(expectedReceiverIdentity) == "" {
		return ErrMissingIdentity
	}
	if strings.TrimSpace(sigHex) == "" {
		return ErrInvalidSignature
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	digest, err := CanonicalPutDigest(expectedSenderIdentity, expectedReceiverIdentity, id, payload, attachments)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return ErrInvalidSignature
	}
	return nil
}

// CanonicalAckDigest computes the unambiguous, length-prefixed canonical SHA-256 digest for an ACK receipt
// binding the message ID to the exact message signature that was accepted and the receiver's identity:
//
//	UMAI-ACK-V1\nrole:<len>:<receiver_identity>\nid:<len>:<id>\nsig:<len>:<message_signature_hex>\n
func CanonicalAckDigest(receiverIdentity string, id string, msgSignatureHex string) ([32]byte, error) {
	if strings.TrimSpace(receiverIdentity) == "" {
		return [32]byte{}, ErrMissingIdentity
	}
	sigClean := strings.TrimSpace(msgSignatureHex)
	data := fmt.Sprintf("UMAI-ACK-V1\nrole:%d:%s\nid:%d:%s\nsig:%d:%s\n",
		len(receiverIdentity), receiverIdentity,
		len(id), id,
		len(sigClean), sigClean,
	)
	return sha256.Sum256([]byte(data)), nil
}

// SignAckReceipt signs an acceptance receipt with the receiver's Ed25519 private key.
func SignAckReceipt(priv ed25519.PrivateKey, receiverIdentity string, id string, msgSignatureHex string) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", ErrSigningNotConfigured
	}
	digest, err := CanonicalAckDigest(receiverIdentity, id, msgSignatureHex)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, digest[:])
	return hex.EncodeToString(sig), nil
}

// VerifyAckReceipt verifies that the receiver genuinely accepted the exact signed message.
func VerifyAckReceipt(pub ed25519.PublicKey, expectedReceiverIdentity string, id string, msgSignatureHex string, receiptHex string) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrSigningNotConfigured
	}
	if strings.TrimSpace(expectedReceiverIdentity) == "" {
		return ErrMissingIdentity
	}
	if strings.TrimSpace(receiptHex) == "" {
		return ErrInvalidReceipt
	}
	sig, err := hex.DecodeString(strings.TrimSpace(receiptHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidReceipt
	}
	digest, err := CanonicalAckDigest(expectedReceiverIdentity, id, msgSignatureHex)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return ErrInvalidReceipt
	}
	return nil
}
