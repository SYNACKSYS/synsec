package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// A reader for the slice of CBOR that WebAuthn actually uses.
//
// Two structures arrive encoded this way: the attestation object a key returns
// when it is registered, and the public key inside it. Both are small maps of
// integers, strings and byte strings. Indefinite lengths, tags, floats and big
// numbers never appear in either, so they are refused rather than supported -
// a decoder that accepts less is a decoder with less to get wrong.
//
// Everything here reads attacker-supplied bytes, so every length is checked
// against what is left of the buffer before anything is allocated.

const (
	// maxDepth bounds nesting. The deepest thing WebAuthn sends is an
	// attestation statement holding an array of certificates: three levels.
	maxDepth = 8

	// maxItems bounds one collection. Nothing legitimate comes close.
	maxItems = 1024
)

var errMalformedCBOR = errors.New("webauthn: malformed CBOR")

type reader struct {
	data []byte
	pos  int
}

// value decodes the next item.
//
// Integers come back as int64, byte strings as []byte, text as string, arrays
// as []any and maps as map[any]any keyed by int64 or string.
func (r *reader) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errMalformedCBOR
	}
	head, err := r.next()
	if err != nil {
		return nil, err
	}
	major, info := head>>5, head&0x1f

	switch major {
	case 0: // unsigned
		n, err := r.argument(info)
		if err != nil {
			return nil, err
		}
		if n > 1<<62 {
			return nil, errMalformedCBOR
		}
		return int64(n), nil

	case 1: // negative
		n, err := r.argument(info)
		if err != nil {
			return nil, err
		}
		if n > 1<<62 {
			return nil, errMalformedCBOR
		}
		return -1 - int64(n), nil

	case 2: // byte string
		return r.chunk(info)

	case 3: // text string
		b, err := r.chunk(info)
		if err != nil {
			return nil, err
		}
		return string(b), nil

	case 4: // array
		count, err := r.count(info)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, count)
		for i := 0; i < count; i++ {
			item, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, nil

	case 5: // map
		count, err := r.count(info)
		if err != nil {
			return nil, err
		}
		out := make(map[any]any, count)
		for i := 0; i < count; i++ {
			key, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			switch key.(type) {
			case int64, string:
			default:
				// A key of any other type would be unusable to look up, and
				// nothing WebAuthn sends has one.
				return nil, errMalformedCBOR
			}
			val, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, duplicate := out[key]; duplicate {
				// Two entries under one key leave which one wins up to the
				// decoder, which is exactly the ambiguity an attacker wants.
				return nil, errMalformedCBOR
			}
			out[key] = val
		}
		return out, nil

	case 7: // simple values
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		default:
			return nil, errMalformedCBOR
		}

	default: // tags and everything else
		return nil, errMalformedCBOR
	}
}

func (r *reader) next() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, errMalformedCBOR
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

// argument reads the length or value that follows the head byte.
func (r *reader) argument(info byte) (uint64, error) {
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		b, err := r.next()
		return uint64(b), err
	case info == 25:
		b, err := r.take(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(b)), nil
	case info == 26:
		b, err := r.take(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(b)), nil
	case info == 27:
		b, err := r.take(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b), nil
	default:
		// 28 to 30 are reserved; 31 is the indefinite length this decoder does
		// not accept.
		return 0, errMalformedCBOR
	}
}

// chunk reads a byte or text string of the announced length.
func (r *reader) chunk(info byte) ([]byte, error) {
	n, err := r.argument(info)
	if err != nil {
		return nil, err
	}
	return r.take(int(n))
}

// count reads the number of items in a collection, refusing any figure the
// remaining bytes could not possibly hold.
func (r *reader) count(info byte) (int, error) {
	n, err := r.argument(info)
	if err != nil {
		return 0, err
	}
	// Each item costs at least one byte, and a map costs two per entry. The
	// cheaper bound is enough to stop a length field that claims a billion.
	if n > maxItems || n > uint64(len(r.data)-r.pos) {
		return 0, errMalformedCBOR
	}
	return int(n), nil
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.pos {
		return nil, errMalformedCBOR
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

// decodeMap reads one CBOR map from the front of data and reports how many
// bytes it took, so a caller can keep the exact encoding or step over it.
func decodeMap(data []byte) (map[any]any, int, error) {
	r := &reader{data: data}
	v, err := r.value(0)
	if err != nil {
		return nil, 0, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, fmt.Errorf("%w: expected a map", errMalformedCBOR)
	}
	return m, r.pos, nil
}

// The lookups below return the zero value when the entry is missing or of the
// wrong type, which every caller then treats as a refusal.

func mapBytes(m map[any]any, key any) []byte {
	b, _ := m[key].([]byte)
	return b
}

func mapString(m map[any]any, key any) string {
	s, _ := m[key].(string)
	return s
}

func mapInt(m map[any]any, key any) (int64, bool) {
	n, ok := m[key].(int64)
	return n, ok
}
