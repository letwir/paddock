package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deszhou/jcs"
)

// JCSCodec implements RFC 8785 canonicalization using the pure-Go deszhou/jcs
// transform. Construct it explicitly with NewJCSCodec; there is intentionally no
// implicit package-global codec or identity fallback.
type JCSCodec struct{}

// NewJCSCodec returns a production JCS codec.
func NewJCSCodec() *JCSCodec { return &JCSCodec{} }

// CanonicalizeJSON converts valid JSON input to RFC 8785 canonical bytes. The
// dependency handles canonical serialization; this boundary additionally
// rejects duplicate members and unsafe integer values required by I-JSON/JCS.
func (JCSCodec) CanonicalizeJSON(input []byte) ([]byte, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}
	return jcs.Transform(input)
}

func validateInput(input []byte) error {
	if !utf8Valid(input) {
		return errors.New("canonical: input is not valid UTF-8")
	}
	if err := validateSurrogates(input); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := readValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("canonical: trailing JSON value")
		}
		return err
	}
	return nil
}

func readValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("canonical: invalid object key")
				}
				if _, ok := seen[key]; ok {
					return fmt.Errorf("canonical: duplicate object member %q", key)
				}
				seen[key] = struct{}{}
				if err := readValue(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := readValue(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
	case json.Number:
		f, err := strconv.ParseFloat(string(value), 64)
		if err != nil {
			return err
		}
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return errors.New("canonical: number outside IEEE-754 range")
		}
		if math.Trunc(f) == f && math.Abs(f) > 9007199254740991 {
			return errors.New("canonical: unsafe integer")
		}
	}
	return nil
}

func utf8Valid(s []byte) bool { return utf8.Valid(s) }

func validateSurrogates(input []byte) error {
	inString := false
	for i := 0; i < len(input); i++ {
		if !inString {
			if input[i] == '"' {
				inString = true
			}
			continue
		}
		if input[i] == '"' {
			inString = false
			continue
		}
		if input[i] != '\\' {
			continue
		}
		i++
		if i >= len(input) {
			break
		}
		if input[i] != 'u' {
			continue
		}
		if i+4 >= len(input) {
			continue
		}
		code, err := strconv.ParseUint(string(input[i+1:i+5]), 16, 16)
		if err != nil {
			continue
		}
		unit := uint16(code)
		if unit >= 0xDC00 && unit <= 0xDFFF {
			return errors.New("canonical: unpaired low surrogate")
		}
		if unit >= 0xD800 && unit <= 0xDBFF {
			if i+10 >= len(input) || input[i+5] != '\\' || input[i+6] != 'u' {
				return errors.New("canonical: unpaired high surrogate")
			}
			low, err := strconv.ParseUint(string(input[i+7:i+11]), 16, 16)
			if err != nil || !utf16.IsSurrogate(rune(low)) || low < 0xDC00 || low > 0xDFFF {
				return errors.New("canonical: unpaired high surrogate")
			}
			i += 10
		}
	}
	return nil
}
