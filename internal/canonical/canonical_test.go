package canonical

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/deszhou/jcs"
)

func TestJCSCodecGoldenVectors(t *testing.T) {
	codec := NewJCSCodec()
	vectors := []struct {
		name, input, want string
	}{
		{"key order", `{"z":0,"a":1}`, `{"a":1,"z":0}`},
		{"UTF-16 key order", `{"\uE000":1,"😀":2}`, `{"😀":2,"":1}`},
		{"unicode and escaping", `{"s":"é\n\t\\\"/"}`, `{"s":"é\n\t\\\"/"}`},
		{"numeric notation and rounding", `[0.000001,1e-7,333333333.33333329,1.0,-0]`, `[0.000001,1e-7,333333333.3333333,1,0]`},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			got, err := codec.CanonicalizeJSON([]byte(vector.input))
			if err != nil {
				t.Fatalf("CanonicalizeJSON: %v", err)
			}
			if string(got) != vector.want {
				t.Fatalf("got %s; want %s", got, vector.want)
			}
		})
	}
}

func TestJCSCodecAcceptsValidSurrogatePair(t *testing.T) {
	got, err := NewJCSCodec().CanonicalizeJSON([]byte(`"\ud83d\ude00"`))
	if err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	if string(got) != `"😀"` {
		t.Fatalf("canonical pair = %s, want %s", got, `"😀"`)
	}
}

func TestDependencyBehaviorForRestrictedInputs(t *testing.T) {
	// v1.1.0 itself rejects duplicate members, but accepts integral values outside
	// the I-JSON safe-integer range. The adapter's preflight is required for the latter.
	if _, err := jcs.Transform([]byte(`{"x":1,"x":2}`)); err == nil {
		t.Fatal("dependency unexpectedly accepted duplicate member")
	}
	if _, err := jcs.Transform([]byte(`9007199254740992`)); err != nil {
		t.Fatalf("dependency behavior changed for unsafe integer: %v", err)
	}
}

func TestJCSCodecRejectsInvalidOrUnsafeInput(t *testing.T) {
	codec := NewJCSCodec()
	for _, input := range []string{
		`{`, `{"x":1,"x":2}`, `"\ud800"`, `"\udc00"`, `9007199254740992`, `-9007199254740992`,
	} {
		t.Run(input, func(t *testing.T) {
			if got, err := codec.CanonicalizeJSON([]byte(input)); err == nil {
				t.Errorf("accepted %s as %s", input, got)
			}
		})
	}
}

func TestJCSCodecRejectsEscapedEquivalentDuplicateKeys(t *testing.T) {
	input := []byte(`{"a":1,"\u0061":2}`)
	if got, err := NewJCSCodec().CanonicalizeJSON(input); err == nil {
		t.Fatalf("accepted escaped-equivalent duplicate keys as %s", got)
	}
}

func TestJCSCodecSafeIntegerBoundary(t *testing.T) {
	codec := NewJCSCodec()
	for _, input := range []string{"9007199254740991", "-9007199254740991"} {
		if got, err := codec.CanonicalizeJSON([]byte(input)); err != nil {
			t.Errorf("rejected safe integer %s: %v", input, err)
		} else if string(got) != input {
			t.Errorf("canonicalize(%s) = %s", input, got)
		}
	}
	for _, input := range []string{"9007199254740992", "-9007199254740992"} {
		if got, err := codec.CanonicalizeJSON([]byte(input)); err == nil {
			t.Errorf("accepted unsafe integer %s as %s", input, got)
		}
	}
}

func TestEnvelopeGoldenUsesJCSCodec(t *testing.T) {
	got, err := Envelope(NewJCSCodec(), DomainApproval, Context{"paddock.approval/1", "governance", "cmd-7", "nonce-9"}, []byte(`{"b":"é","a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"audience":"governance","domain":"paddock.approval","nonce":"nonce-9","payload":{"a":1,"b":"é"},"request_id":"cmd-7","schema_version":"paddock.approval/1"}`
	if string(got) != want {
		t.Fatalf("envelope mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestEnvelopeSeparatesDomainSchemaAndReplayContext(t *testing.T) {
	codec := NewJCSCodec()
	base := Context{"v1", "aud", "id", "nonce"}
	first, err := Envelope(codec, DomainBundle, base, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		domain Domain
		ctx    Context
	}{
		{DomainApproval, base},
		{DomainBundle, Context{"v2", "aud", "id", "nonce"}},
		{DomainBundle, Context{"v1", "other", "id", "nonce"}},
		{DomainBundle, Context{"v1", "aud", "other-id", "nonce"}},
		{DomainBundle, Context{"v1", "aud", "id", "other-nonce"}},
	}
	for _, v := range variants {
		got, err := Envelope(codec, v.domain, v.ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, got) {
			t.Fatalf("context change did not change envelope: %+v", v)
		}
	}
}

func TestEnvelopeSignatureCannotCrossProtocol(t *testing.T) {
	codec := NewJCSCodec()
	payload := []byte(`{"value":1}`)
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	pairs := []struct {
		name            string
		signingDomain   Domain
		verifyingDomain Domain
		signingSchema   string
		verifyingSchema string
	}{
		{"Bundle to Approval", DomainBundle, DomainApproval, "paddock.bundle/1", "paddock.approval/1"},
		{"Bundle to Command", DomainBundle, DomainCommand, "paddock.bundle/1", "paddock.command/1"},
		{"Approval to Command", DomainApproval, DomainCommand, "paddock.approval/1", "paddock.command/1"},
	}
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			ctx := Context{pair.signingSchema, "governance", "request-1", "nonce-1"}
			signingEnvelope, err := Envelope(codec, pair.signingDomain, ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			ctx.SchemaVersion = pair.verifyingSchema
			verifyingEnvelope, err := Envelope(codec, pair.verifyingDomain, ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(privateKey, signingEnvelope)
			if !ed25519.Verify(publicKey, signingEnvelope, signature) {
				t.Fatal("signature did not verify for its own envelope")
			}
			if ed25519.Verify(publicKey, verifyingEnvelope, signature) {
				t.Fatalf("%s signature verified as %s", pair.signingDomain, pair.verifyingDomain)
			}
		})
	}
}

func TestEnvelopeFailsClosed(t *testing.T) {
	ctx := Context{"v1", "aud", "id", "nonce"}
	if _, err := Envelope(nil, DomainBundle, ctx, []byte(`{}`)); !errors.Is(err, ErrNoCodec) {
		t.Fatalf("got %v", err)
	}
	if _, err := Envelope(NewJCSCodec(), "", ctx, []byte(`{}`)); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("got %v", err)
	}
	ctx.SchemaVersion = ""
	if _, err := Envelope(NewJCSCodec(), DomainBundle, ctx, []byte(`{}`)); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("got %v", err)
	}
	ctx.SchemaVersion, ctx.Nonce = "v1", ""
	if _, err := Envelope(NewJCSCodec(), DomainBundle, ctx, []byte(`{}`)); !errors.Is(err, ErrInvalidReplay) {
		t.Fatalf("got %v", err)
	}
}
