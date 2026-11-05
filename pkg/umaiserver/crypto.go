package umaiserver

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrInvalidSignature = errors.New("invalid or missing cryptographic signature")
	ErrInvalidReceipt   = errors.New("invalid or missing cryptographic ACK receipt")
)

// DeriveDemoKeyPair deterministically derives an Ed25519 key pair for a standard role ("app-a" or "app-b")
// so local development and automated tests work out of the box with zero manual setup.
// Production deployments can override keys via UMAI_SIGNING_PRIVATE_KEY and UMAI_PEER_PUBLIC_KEY.
func DeriveDemoKeyPair(role string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("UMAI-0.1-DEMO-ED25519-SEED:" + role))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// ParseKeyPair parses hex-encoded Ed25519 private (seed or 64-byte key) and peer public keys,
// falling back to deterministic role keys if empty.
func ParseKeyPair(role, privHex, peerPubHex string) (ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, error) {
	ownPub, ownPriv := DeriveDemoKeyPair(role)
	if privHex != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(privHex))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decoding signing private key hex: %w", err)
		}
		switch len(raw) {
		case ed25519.SeedSize:
			ownPriv = ed25519.NewKeyFromSeed(raw)
			ownPub = ownPriv.Public().(ed25519.PublicKey)
		case ed25519.PrivateKeySize:
			ownPriv = ed25519.PrivateKey(raw)
			ownPub = ownPriv.Public().(ed25519.PublicKey)
		default:
			return nil, nil, nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(raw))
		}
	}

	peerRole := "app-b"
	if role == "app-b" {
		peerRole = "app-a"
	}
	peerPub, _ := DeriveDemoKeyPair(peerRole)
	if peerPubHex != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(peerPubHex))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("decoding peer public key hex: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, nil, nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(raw))
		}
		peerPub = ed25519.PublicKey(raw)
	}

	return ownPub, ownPriv, peerPub, nil
}

// CanonicalPutDigest computes the canonical SHA-256 digest of a UMAI PUT message:
//
//	UMAI-PUT-V1\n<id>\n<payload_canonical_sha256>\n<att1_name>:<att1_size>:<att1_sha256>\n...
//
// Attachments are sorted by sanitized name so ordering differences never break verification.
func CanonicalPutDigest(id string, payload any, attachments []AttachmentInfo) ([32]byte, error) {
	// Normalize payload through JSON round-trip so map types and json.Unmarshal outputs produce identical JSON
	var normalized any
	rawBytes, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, err
	}
	if len(rawBytes) > 0 && string(rawBytes) != "null" {
		_ = json.Unmarshal(rawBytes, &normalized)
	}
	canonicalPayload, err := json.Marshal(normalized)
	if err != nil {
		return [32]byte{}, err
	}
	payloadHash := sha256.Sum256(canonicalPayload)

	sortedAtts := make([]AttachmentInfo, len(attachments))
	copy(sortedAtts, attachments)
	sort.Slice(sortedAtts, func(i, j int) bool {
		return sortedAtts[i].Name < sortedAtts[j].Name
	})

	var sb strings.Builder
	sb.WriteString("UMAI-PUT-V1\n")
	sb.WriteString(id)
	sb.WriteString("\n")
	sb.WriteString(hex.EncodeToString(payloadHash[:]))
	sb.WriteString("\n")
	for _, a := range sortedAtts {
		sb.WriteString(fmt.Sprintf("%s:%d:%s\n", a.Name, a.Size, a.SHA256))
	}

	return sha256.Sum256([]byte(sb.String())), nil
}

// SignPutMessage signs a message's canonical PUT digest with the sender's Ed25519 private key.
func SignPutMessage(priv ed25519.PrivateKey, id string, payload any, attachments []AttachmentInfo) (string, error) {
	if len(priv) == 0 {
		return "", nil
	}
	digest, err := CanonicalPutDigest(id, payload, attachments)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, digest[:])
	return hex.EncodeToString(sig), nil
}

// VerifyPutMessage verifies a message's canonical PUT digest against the sender's Ed25519 public key.
func VerifyPutMessage(pub ed25519.PublicKey, id string, payload any, attachments []AttachmentInfo, sigHex string) error {
	if len(pub) == 0 {
		return nil
	}
	if strings.TrimSpace(sigHex) == "" {
		return ErrInvalidSignature
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	digest, err := CanonicalPutDigest(id, payload, attachments)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return ErrInvalidSignature
	}
	return nil
}

// CanonicalAckDigest computes the canonical SHA-256 digest for an ACK receipt binding the message ID
// to the exact message signature that was accepted:
//
//	UMAI-ACK-V1\n<id>\n<message_signature_hex>
func CanonicalAckDigest(id string, msgSignatureHex string) [32]byte {
	data := fmt.Sprintf("UMAI-ACK-V1\n%s\n%s\n", id, strings.TrimSpace(msgSignatureHex))
	return sha256.Sum256([]byte(data))
}

// SignAckReceipt signs an acceptance receipt with the receiver's Ed25519 private key.
func SignAckReceipt(priv ed25519.PrivateKey, id string, msgSignatureHex string) string {
	if len(priv) == 0 {
		return ""
	}
	digest := CanonicalAckDigest(id, msgSignatureHex)
	sig := ed25519.Sign(priv, digest[:])
	return hex.EncodeToString(sig)
}

// VerifyAckReceipt verifies that the receiver genuinely accepted the exact signed message.
func VerifyAckReceipt(pub ed25519.PublicKey, id string, msgSignatureHex string, receiptHex string) error {
	if len(pub) == 0 {
		return nil
	}
	if strings.TrimSpace(receiptHex) == "" {
		return ErrInvalidReceipt
	}
	sig, err := hex.DecodeString(strings.TrimSpace(receiptHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidReceipt
	}
	digest := CanonicalAckDigest(id, msgSignatureHex)
	if !ed25519.Verify(pub, digest[:], sig) {
		return ErrInvalidReceipt
	}
	return nil
}
