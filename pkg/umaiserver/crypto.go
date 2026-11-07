package umaiserver

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

// CanonicalPutDigest computes the unambiguous, length-prefixed canonical SHA-256 digest of a UMAI PUT message:
//
//	UMAI-PUT-V1\n
//	sender:<len>:<sender_role>\n
//	receiver:<len>:<receiver_role>\n
//	id:<len>:<id>\n
//	payload:<payload_canonical_sha256>\n
//	att_count:<count>\n
//	att:<name_len>:<att1_name>:<att1_size>:<att1_sha256>\n...
//
// Binding both sender and intended receiver prevents cross-channel or multi-peer misdirection,
// length-prefixing variable-length strings guarantees injectivity (zero delimiter collision ambiguity),
// and sorting attachments by sanitized name ensures ordering differences never break verification.
func CanonicalPutDigest(senderRole string, receiverRole string, id string, payload any, attachments []AttachmentInfo) ([32]byte, error) {
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
	copy(sortedAtts, attachments)
	sort.Slice(sortedAtts, func(i, j int) bool {
		return sortedAtts[i].Name < sortedAtts[j].Name
	})

	var sb strings.Builder
	sb.WriteString("UMAI-PUT-V1\n")
	sb.WriteString(fmt.Sprintf("sender:%d:%s\n", len(senderRole), senderRole))
	sb.WriteString(fmt.Sprintf("receiver:%d:%s\n", len(receiverRole), receiverRole))
	sb.WriteString(fmt.Sprintf("id:%d:%s\n", len(id), id))
	sb.WriteString(fmt.Sprintf("payload:%s\n", hex.EncodeToString(payloadHash[:])))
	sb.WriteString(fmt.Sprintf("att_count:%d\n", len(sortedAtts)))
	for _, a := range sortedAtts {
		sb.WriteString(fmt.Sprintf("att:%d:%s:%d:%s\n", len(a.Name), a.Name, a.Size, a.SHA256))
	}

	return sha256.Sum256([]byte(sb.String())), nil
}

// SignPutMessage signs a message's canonical PUT digest (binding sender and intended receiver) with the sender's Ed25519 private key.
func SignPutMessage(priv ed25519.PrivateKey, senderRole string, receiverRole string, id string, payload any, attachments []AttachmentInfo) (string, error) {
	if len(priv) == 0 {
		return "", nil
	}
	digest, err := CanonicalPutDigest(senderRole, receiverRole, id, payload, attachments)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, digest[:])
	return hex.EncodeToString(sig), nil
}

// VerifyPutMessage verifies a message's canonical PUT digest against the sender's Ed25519 public key and expected sender/receiver roles.
func VerifyPutMessage(pub ed25519.PublicKey, expectedSenderRole string, expectedReceiverRole string, id string, payload any, attachments []AttachmentInfo, sigHex string) error {
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
	digest, err := CanonicalPutDigest(expectedSenderRole, expectedReceiverRole, id, payload, attachments)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest[:], sig) {
		return ErrInvalidSignature
	}
	return nil
}

// CanonicalAckDigest computes the unambiguous, length-prefixed canonical SHA-256 digest for an ACK receipt
// binding the message ID to the exact message signature that was accepted and the receiver's role:
//
//	UMAI-ACK-V1\nrole:<len>:<receiver_role>\nid:<len>:<id>\nsig:<len>:<message_signature_hex>\n
func CanonicalAckDigest(receiverRole string, id string, msgSignatureHex string) [32]byte {
	sigClean := strings.TrimSpace(msgSignatureHex)
	data := fmt.Sprintf("UMAI-ACK-V1\nrole:%d:%s\nid:%d:%s\nsig:%d:%s\n",
		len(receiverRole), receiverRole,
		len(id), id,
		len(sigClean), sigClean,
	)
	return sha256.Sum256([]byte(data))
}

// SignAckReceipt signs an acceptance receipt with the receiver's Ed25519 private key.
func SignAckReceipt(priv ed25519.PrivateKey, receiverRole string, id string, msgSignatureHex string) string {
	if len(priv) == 0 {
		return ""
	}
	digest := CanonicalAckDigest(receiverRole, id, msgSignatureHex)
	sig := ed25519.Sign(priv, digest[:])
	return hex.EncodeToString(sig)
}

// VerifyAckReceipt verifies that the receiver genuinely accepted the exact signed message.
func VerifyAckReceipt(pub ed25519.PublicKey, expectedReceiverRole string, id string, msgSignatureHex string, receiptHex string) error {
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
	digest := CanonicalAckDigest(expectedReceiverRole, id, msgSignatureHex)
	if !ed25519.Verify(pub, digest[:], sig) {
		return ErrInvalidReceipt
	}
	return nil
}
