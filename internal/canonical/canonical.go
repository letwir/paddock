// Package canonical defines RFC 8785 canonical bytes and the versioned,
// domain-separated input contract for deterministic signing and request digests.
// Callers explicitly construct and supply the production JCSCodec; nil fails closed.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrNoCodec       = errors.New("canonical: no RFC 8785 JCS codec configured")
	ErrInvalidDomain = errors.New("canonical: invalid domain")
	ErrInvalidSchema = errors.New("canonical: schema version is required")
	ErrInvalidReplay = errors.New("canonical: anti-replay context is incomplete")
)

// Domain separates otherwise identical payloads used by distinct protocols.
type Domain string

const (
	DomainBundle   Domain = "paddock.bundle"
	DomainApproval Domain = "paddock.approval"
	DomainCommand  Domain = "paddock.command"
)

// Context is signed along with the payload to prevent cross-protocol and
// cross-instance replay. Values are explicit caller-supplied identifiers, not
// generated from ambient clocks or randomness.
type Context struct {
	SchemaVersion string
	Audience      string
	RequestID     string
	Nonce         string
}

// Envelope serializes a domain-separated signing input. Payload and context are
// canonicalized separately, then placed in a canonical JSON object. A nil codec
// fails closed; only the production JCSCodec can be supplied.
func Envelope(codec *JCSCodec, domain Domain, ctx Context, payload []byte) ([]byte, error) {
	if codec == nil {
		return nil, ErrNoCodec
	}
	if !validDomain(domain) {
		return nil, ErrInvalidDomain
	}
	if ctx.SchemaVersion == "" {
		return nil, ErrInvalidSchema
	}
	if ctx.Audience == "" || ctx.RequestID == "" || ctx.Nonce == "" {
		return nil, ErrInvalidReplay
	}
	canonicalPayload, err := codec.CanonicalizeJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalize payload: %w", err)
	}
	// Constructing through a fixed template keeps the envelope structure stable;
	// the codec owns all escaping and canonical JSON rules.
	strings := []string{ctx.Audience, string(domain), ctx.Nonce, ctx.RequestID, ctx.SchemaVersion}
	quoted := make([][]byte, len(strings))
	for i, value := range strings {
		quoted[i], err = json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode envelope string: %w", err)
		}
	}
	input := []byte(fmt.Sprintf(`{"audience":%s,"domain":%s,"nonce":%s,"payload":%s,"request_id":%s,"schema_version":%s}`,
		quoted[0], quoted[1], quoted[2], canonicalPayload, quoted[3], quoted[4]))
	out, err := codec.CanonicalizeJSON(input)
	if err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	if !bytes.HasPrefix(out, []byte("{")) {
		return nil, errors.New("canonicalize envelope: codec returned non-object")
	}
	return out, nil
}

func validDomain(d Domain) bool {
	if len(d) == 0 || len(d) > 128 {
		return false
	}
	for _, r := range string(d) {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
