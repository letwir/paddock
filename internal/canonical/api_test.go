package canonical_test

import (
	"reflect"
	"testing"

	"github.com/letwir/paddock/internal/canonical"
)

// identityCodec demonstrates the arbitrary implementation that the public API
// must not accept. Envelope's concrete parameter type makes passing it a compile
// error, regardless of this matching method set.
type identityCodec struct{}

func (identityCodec) CanonicalizeJSON(input []byte) ([]byte, error) { return input, nil }

func TestEnvelopeRequiresConcreteProductionCodec(t *testing.T) {
	codecType := reflect.TypeOf(canonical.Envelope).In(0)
	want := reflect.TypeOf((*canonical.JCSCodec)(nil))
	if codecType != want {
		t.Fatalf("Envelope codec parameter = %v, want %v", codecType, want)
	}
	var _ interface{ CanonicalizeJSON([]byte) ([]byte, error) } = identityCodec{}
}
