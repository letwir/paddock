package domain

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/letwir/paddock/internal/canonical"
)

var ErrInvalidCanonicalInput = errors.New("invalid canonical input")

const commandSchemaVersion = "paddock.command/1"

// CanonicalRequest is an immutable-by-contract JCS command request.
type CanonicalRequest struct {
	commandID string
	nonce     string
	payload   []byte
	signing   []byte
	digest    Digest
}

func NewCanonicalRequest(commandID, nonce string, payload []byte) (CanonicalRequest, error) {
	if validateID(commandID) != nil || validateID(nonce) != nil {
		return CanonicalRequest{}, fmt.Errorf("%w: command ID and nonce required", ErrInvalidCanonicalInput)
	}
	codec := canonical.NewJCSCodec()
	canonicalPayload, err := codec.CanonicalizeJSON(payload)
	if err != nil {
		return CanonicalRequest{}, fmt.Errorf("%w: %v", ErrInvalidCanonicalInput, err)
	}
	context := canonical.Context{SchemaVersion: commandSchemaVersion, Audience: "governance", RequestID: commandID, Nonce: nonce}
	signing, err := canonical.Envelope(codec, canonical.DomainCommand, context, canonicalPayload)
	if err != nil {
		return CanonicalRequest{}, fmt.Errorf("%w: %v", ErrInvalidCanonicalInput, err)
	}
	hash := sha256.Sum256(signing)
	return CanonicalRequest{commandID: commandID, nonce: nonce, payload: cloneCanonicalBytes(canonicalPayload), signing: cloneCanonicalBytes(signing), digest: Digest(fmt.Sprintf("%x", hash[:]))}, nil
}

func (r CanonicalRequest) PayloadBytes() []byte { return cloneCanonicalBytes(r.payload) }
func (r CanonicalRequest) SigningBytes() []byte { return cloneCanonicalBytes(r.signing) }
func (r CanonicalRequest) Digest() Digest       { return r.digest }

func (r CanonicalRequest) Validate() error {
	computed, err := NewCanonicalRequest(r.commandID, r.nonce, r.payload)
	if err != nil || computed.digest != r.digest || !equalBytes(computed.signing, r.signing) || !equalBytes(computed.payload, r.payload) {
		return ErrInvalidCanonicalInput
	}
	return nil
}

// CanonicalBundle separates content identity from context-bound signing bytes.
type CanonicalBundle struct {
	schemaVersion string
	bundleID      string
	nonce         string
	payload       []byte
	signing       []byte
	digest        Digest
}

func NewCanonicalBundle(schemaVersion string, payload []byte) (CanonicalBundle, error) {
	if validateID(schemaVersion) != nil {
		return CanonicalBundle{}, fmt.Errorf("%w: schema version required", ErrInvalidCanonicalInput)
	}
	codec := canonical.NewJCSCodec()
	canonicalPayload, err := codec.CanonicalizeJSON(payload)
	if err != nil {
		return CanonicalBundle{}, fmt.Errorf("%w: %v", ErrInvalidCanonicalInput, err)
	}
	hash := sha256.Sum256(canonicalPayload)
	requestID := fmt.Sprintf("%x", hash[:])
	nonceHash := sha256.New()
	_, _ = nonceHash.Write([]byte("PADDOCK-BUNDLE-NONCE-v1\x00"))
	_, _ = nonceHash.Write(hash[:])
	nonce := fmt.Sprintf("%x", nonceHash.Sum(nil))
	context := canonical.Context{SchemaVersion: schemaVersion, Audience: "governance", RequestID: requestID, Nonce: nonce}
	signing, err := canonical.Envelope(codec, canonical.DomainBundle, context, canonicalPayload)
	if err != nil {
		return CanonicalBundle{}, fmt.Errorf("%w: %v", ErrInvalidCanonicalInput, err)
	}
	return CanonicalBundle{schemaVersion: schemaVersion, bundleID: requestID, nonce: nonce, payload: cloneCanonicalBytes(canonicalPayload), signing: cloneCanonicalBytes(signing), digest: Digest(requestID)}, nil
}

func (b CanonicalBundle) CanonicalBytes() []byte { return cloneCanonicalBytes(b.payload) }
func (b CanonicalBundle) SigningBytes() []byte   { return cloneCanonicalBytes(b.signing) }
func (b CanonicalBundle) SchemaVersion() string  { return b.schemaVersion }
func (b CanonicalBundle) BundleID() string       { return b.bundleID }
func (b CanonicalBundle) RequestID() string      { return b.bundleID }
func (b CanonicalBundle) Nonce() string          { return b.nonce }
func (b CanonicalBundle) Digest() Digest         { return b.digest }

func (b CanonicalBundle) Validate() error {
	computed, err := NewCanonicalBundle(b.schemaVersion, b.payload)
	if err != nil || computed.digest != b.digest || computed.bundleID != b.bundleID || computed.nonce != b.nonce || !equalBytes(computed.payload, b.payload) || !equalBytes(computed.signing, b.signing) {
		return ErrInvalidCanonicalInput
	}
	return nil
}

func cloneCanonicalBytes(value []byte) []byte { return append([]byte(nil), value...) }
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
