package canonical

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"strconv"
	"testing"
)

func TestJCSRFC8785PropertyOrderAndEscaping(t *testing.T) {
	vectors := []struct{ input, want string }{
		// RFC 8785 section 3.2.3, including a supplementary-plane key.
		{`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`, "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"},
		{`{"a\ud83d\ude00":1,"a\ue000":2,"a":3,"aa":4}`, `{"a":3,"aa":4,"a😀":1,"a":2}`},
		{`{"z":[{"\ue000":0,"\ud83d\ude00":1}],"a":{"z":null,"a":true,"b":false}}`, `{"a":{"a":true,"b":false,"z":null},"z":[{"😀":1,"":0}]}`},
		{`"\u0000\u0001\u0008\u0009\u000a\u000b\u000c\u000d\u001f\u0022\u005c\/<>\u0026\u2028\u2029"`, "\"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\\\"\\\\/<>&\u2028\u2029\""},
		// No Unicode normalization: these two spellings stay distinct.
		{`["\u00e9","e\u0301"]`, `["é","é"]`},
		{`"\\ud800"`, `"\\ud800"`},
		{` { "b": [ ] , "a": { } } `, `{"a":{},"b":[]}`},
	}
	for _, v := range vectors {
		got, err := NewJCSCodec().CanonicalizeJSON([]byte(v.input))
		if err != nil || string(got) != v.want {
			t.Fatalf("canonicalize(%s) = %s, %v; want %s", v.input, got, err, v.want)
		}
	}
	// All control characters, not just the short-escape examples.
	var controls string
	for i := 0; i < 32; i++ {
		controls += string(rune(i))
	}
	input, err := json.Marshal(controls)
	if err != nil {
		t.Fatal(err)
	}
	const want = `"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`
	got, err := NewJCSCodec().CanonicalizeJSON(input)
	if err != nil || string(got) != want {
		t.Fatalf("controls = %s, %v", got, err)
	}
}

func TestJCSNumberRFC8785AppendixB(t *testing.T) {
	// Test the binary64 serializer directly: some RFC vectors are deliberately
	// outside this repository's stricter public safe-integer profile.
	vectors := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"}, {0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"}, {0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"}, {0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"}, {0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"}, {0x44b52d02c7e14af6, "1e+23"}, {0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"}, {0x444b1ae4d6e2ef4f, "999999999999999900000"}, {0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"}, {0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"}, {0x41b3de4355555554, "333333333.33333325"}, {0x41b3de4355555555, "333333333.3333333"}, {0x41b3de4355555556, "333333333.3333334"}, {0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"}, {0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, v := range vectors {
		if got := string(appendJCSNumber(nil, math.Float64frombits(v.bits))); got != v.want {
			t.Errorf("%016x = %s; want %s", v.bits, got, v.want)
		}
	}
}

func TestJCSNumberPublicBoundary(t *testing.T) {
	for _, v := range []struct{ input, want string }{
		{"-0.0", "0"}, {"-0e10", "0"}, {"1e-6", "0.000001"}, {"1e-7", "1e-7"},
		{"0.0000010000000000000002", "0.0000010000000000000002"},
		{"5e-324", "5e-324"}, {"2.2250738585072014e-308", "2.2250738585072014e-308"},
		{"1e-999", "0"}, {"-1e-999", "0"},
		{"4.50", "4.5"}, {"2e-3", "0.002"}, {"1e-27", "1e-27"},
		{"333333333.33333329", "333333333.3333333"}, {"1424953923781206.25", "1424953923781206.2"},
	} {
		got, err := NewJCSCodec().CanonicalizeJSON([]byte(v.input))
		if err != nil || string(got) != v.want {
			t.Errorf("%s = %s, %v; want %s", v.input, got, err, v.want)
		}
	}
	for _, input := range []string{"1e21", "1e20", "9007199254740992.0", "-9007199254740992e0", "1e400", "-1e400", "NaN", "Infinity"} {
		if got, err := NewJCSCodec().CanonicalizeJSON([]byte(input)); err == nil {
			t.Errorf("accepted %s as %s", input, got)
		}
	}
}

func TestJCSStrictOriginalJSONValidation(t *testing.T) {
	invalid := [][]byte{
		{'"', 0xff, '"'}, []byte("\"\xed\xa0\x80\""), []byte("\"\xc0\xaf\""),
		[]byte(`"\ud800x"`), []byte(`"\ud800\u0041"`), []byte(`"\udc00\ud800"`),
		[]byte(`{"x":{"a":0,"\u0061":1}}`), []byte(`{"😀":0,"\ud83d\ude00":1}`),
		[]byte(`{}[]`), []byte(`true false`), []byte(`null!`), []byte("\xef\xbb\xbf{}"),
		[]byte(`01`), []byte(`1.`), []byte(`+1`), []byte(`"\x20"`), []byte("\"\x01\""), nil,
	}
	for _, input := range invalid {
		if got, err := NewJCSCodec().CanonicalizeJSON(input); err == nil {
			t.Errorf("accepted %q as %s", input, got)
		}
	}
}

func TestJCSNumberRoundTripAndCanonicalIdempotence(t *testing.T) {
	random := rand.New(rand.NewSource(8785))
	for i := 0; i < 10000; i++ {
		f := math.Float64frombits(random.Uint64())
		if math.IsInf(f, 0) || math.IsNaN(f) {
			continue
		}
		encoded := appendJCSNumber(nil, f)
		back, err := strconv.ParseFloat(string(encoded), 64)
		if err != nil || back != f {
			t.Fatalf("%x roundtrip: %s, %v", math.Float64bits(f), encoded, err)
		}
		if math.Trunc(f) == f && math.Abs(f) > 9007199254740991 {
			continue
		}
		canonical, err := NewJCSCodec().CanonicalizeJSON(encoded)
		if err != nil || !bytes.Equal(canonical, encoded) {
			t.Fatalf("%s not idempotent: %s, %v", encoded, canonical, err)
		}
	}
}
