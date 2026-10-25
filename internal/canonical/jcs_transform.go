package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// transformJCS is reached only after validateInput has checked the ORIGINAL
// bytes: encoding/json alone replaces invalid Unicode and loses duplicate keys.
func transformJCS(input []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("canonical: decode validated JSON: %w", err)
	}
	return appendJCSValue(nil, value)
}

func appendJCSValue(dst []byte, value any) ([]byte, error) {
	switch v := value.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		return strconv.AppendBool(dst, v), nil
	case string:
		return appendJCSString(dst, v), nil
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return nil, fmt.Errorf("canonical: binary64 number: %w", err)
		}
		return appendJCSNumber(dst, f), nil
	case []any:
		dst = append(dst, '[')
		for i, item := range v {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			dst, err = appendJCSValue(dst, item)
			if err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		// Precompute code units: Go's native string order is UTF-8, not the
		// UTF-16 order required by RFC 8785 section 3.2.3.
		type property struct {
			name  string
			units []uint16
		}
		properties := make([]property, 0, len(v))
		for name := range v {
			properties = append(properties, property{name, utf16.Encode([]rune(name))})
		}
		sort.Slice(properties, func(i, j int) bool {
			a, b := properties[i].units, properties[j].units
			for k := 0; k < len(a) && k < len(b); k++ {
				if a[k] != b[k] {
					return a[k] < b[k]
				}
			}
			return len(a) < len(b)
		})
		dst = append(dst, '{')
		for i, p := range properties {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJCSString(dst, p.name)
			dst = append(dst, ':')
			var err error
			dst, err = appendJCSValue(dst, v[p.name])
			if err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, fmt.Errorf("canonical: unsupported decoded type %T", value)
	}
}

func appendJCSString(dst []byte, value string) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	// Valid UTF-8 is copied byte-for-byte, including HTML-sensitive characters
	// and U+2028/U+2029. Neither Go quoting nor json.Marshal has JCS escaping.
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\b':
			dst = append(dst, `\b`...)
		case '\t':
			dst = append(dst, `\t`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\f':
			dst = append(dst, `\f`...)
		case '\r':
			dst = append(dst, `\r`...)
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&15])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}

// appendJCSNumber serializes a finite binary64 using ECMAScript Number::toString
// (RFC 8785 section 3.2.2.3). Go's shortest-roundtrip conversion selects the same
// nearest decimal significand (ties to even), but its 'g' notation thresholds
// and exponent padding differ. Use 'e' to obtain those digits, then apply the
// ECMAScript decimal-point rules explicitly. The public boundary separately
// enforces the repository's safe-integer profile.
func appendJCSNumber(dst []byte, value float64) []byte {
	if value == 0 {
		return append(dst, '0') // includes IEEE-754 negative zero
	}
	if value < 0 {
		dst = append(dst, '-')
		value = -value
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	e := strings.IndexByte(scientific, 'e')
	// FormatFloat always emits a signed exponent with at least two digits.
	exponent := 0
	for i := e + 2; i < len(scientific); i++ {
		exponent = exponent*10 + int(scientific[i]-'0')
	}
	if scientific[e+1] == '-' {
		exponent = -exponent
	}
	digits := strings.ReplaceAll(scientific[:e], ".", "")
	point := exponent + 1
	switch {
	case point > 0 && point <= 21:
		if point >= len(digits) {
			dst = append(dst, digits...)
			for i := len(digits); i < point; i++ {
				dst = append(dst, '0')
			}
		} else {
			dst = append(dst, digits[:point]...)
			dst = append(dst, '.')
			dst = append(dst, digits[point:]...)
		}
	case point <= 0 && point > -6:
		dst = append(dst, '0', '.')
		for i := 0; i < -point; i++ {
			dst = append(dst, '0')
		}
		dst = append(dst, digits...)
	default:
		dst = append(dst, digits[0])
		if len(digits) > 1 {
			dst = append(dst, '.')
			dst = append(dst, digits[1:]...)
		}
		dst = append(dst, 'e')
		if exponent >= 0 {
			dst = append(dst, '+')
		}
		dst = strconv.AppendInt(dst, int64(exponent), 10)
	}
	return dst
}
