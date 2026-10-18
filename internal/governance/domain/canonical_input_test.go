package domain

import (
	"bytes"
	"testing"
)

func TestCanonicalRequestJCSContextAndCopies(t *testing.T) {
	a, err := NewCanonicalRequest("cmd-1", "nonce-1", []byte(`{"b":1.0,"a": 2}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCanonicalRequest("cmd-1", "nonce-1", []byte("{\n \"a\":2.0,\"b\":1 \n}"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() || !bytes.Equal(a.SigningBytes(), b.SigningBytes()) {
		t.Fatal("JCS-equivalent requests differ")
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, nonce string }{{"cmd-2", "nonce-1"}, {"cmd-1", "nonce-2"}} {
		changed, err := NewCanonicalRequest(tc.id, tc.nonce, []byte(`{"a":2,"b":1}`))
		if err != nil {
			t.Fatal(err)
		}
		if changed.Digest() == a.Digest() || bytes.Equal(changed.SigningBytes(), a.SigningBytes()) {
			t.Fatal("changed request context did not change signing digest")
		}
	}
	payload, signing := a.PayloadBytes(), a.SigningBytes()
	payload[0], signing[0] = 'x', 'x'
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalBundleContentAndContext(t *testing.T) {
	a, err := NewCanonicalBundle("paddock.bundle/1", []byte(`{"n":1.0,"x":true}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCanonicalBundle("paddock.bundle/1", []byte("{ \"x\":true,\"n\":1 }"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() || !bytes.Equal(a.CanonicalBytes(), b.CanonicalBytes()) {
		t.Fatal("content digest depends on context or JCS variant")
	}
	if a.BundleID() != b.BundleID() || a.RequestID() != b.RequestID() || a.Nonce() != b.Nonce() || !bytes.Equal(a.SigningBytes(), b.SigningBytes()) {
		t.Fatal("same content did not produce identical derived context and signing bytes")
	}
	otherSchema, err := NewCanonicalBundle("paddock.bundle/2", []byte(`{"x":true,"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if otherSchema.Digest() != a.Digest() || otherSchema.RequestID() != a.RequestID() || otherSchema.Nonce() != a.Nonce() || bytes.Equal(otherSchema.SigningBytes(), a.SigningBytes()) {
		t.Fatal("schema version must affect signing bytes, not content-derived context")
	}
	changed, err := NewCanonicalBundle("paddock.bundle/1", []byte(`{"n":2,"x":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if changed.Digest() == a.Digest() || changed.RequestID() == a.RequestID() || changed.Nonce() == a.Nonce() || bytes.Equal(changed.SigningBytes(), a.SigningBytes()) {
		t.Fatal("changed content did not change derived context")
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	content, signing := a.CanonicalBytes(), a.SigningBytes()
	content[0], signing[0] = 'x', 'x'
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalValuesRejectInvalidContextAndJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"empty command", func() error { _, e := NewCanonicalRequest("", "n", []byte(`{}`)); return e }},
		{"trim command", func() error { _, e := NewCanonicalRequest(" cmd", "n", []byte(`{}`)); return e }},
		{"empty nonce", func() error { _, e := NewCanonicalRequest("c", "", []byte(`{}`)); return e }},
		{"duplicate", func() error { _, e := NewCanonicalRequest("c", "n", []byte(`{"x":1,"x":2}`)); return e }},
		{"unsafe integer", func() error { _, e := NewCanonicalBundle("s", []byte(`9007199254740992`)); return e }},
		{"malformed", func() error { _, e := NewCanonicalRequest("c", "n", []byte(`{`)); return e }},
		{"bundle schema", func() error { _, e := NewCanonicalBundle(" ", []byte(`{}`)); return e }},
		{"bundle malformed", func() error { _, e := NewCanonicalBundle("s", []byte(`{`)); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.run() == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}
