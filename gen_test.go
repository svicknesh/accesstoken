package accesstoken

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jxskiss/base62"
)

func TestGenerate(t *testing.T) {

	const prefix = "abc"

	token, err := Generate(prefix, Separator, RandomBytesLen)
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(token, prefix+Separator) {
		t.Fatalf("token %q does not start with prefix %q and separator %q", token, prefix, Separator)
	}

	if !IsChecksumOK(prefix, Separator, token) {
		t.Fatalf("expected freshly generated token %q to have a valid checksum", token)
	}
}

func TestGenerate_InvalidRandBytesLen(t *testing.T) {

	for _, n := range []int{0, -1, -100} {
		_, err := Generate("abc", Separator, n)
		if !errors.Is(err, ErrInvalidRandBytesLen) {
			t.Errorf("Generate with randBytesLen=%d: expected ErrInvalidRandBytesLen, got %v", n, err)
		}
	}
}

func TestGenerate_BoundaryLengths(t *testing.T) {

	for _, n := range []int{1, 2, 16, 32, 64, 256} {
		token, err := Generate("abc", Separator, n)
		if nil != err {
			t.Fatalf("randBytesLen=%d: unexpected error: %v", n, err)
		}
		if !IsChecksumOK("abc", Separator, token) {
			t.Fatalf("randBytesLen=%d: expected valid checksum for token %q", n, token)
		}
	}
}

func TestGenerate_ProducesDistinctTokens(t *testing.T) {

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := Generate("abc", Separator, RandomBytesLen)
		if nil != err {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[token] {
			t.Fatalf("Generate produced a duplicate token: %q", token)
		}
		seen[token] = true
	}
}

func TestIsChecksumOK_TamperedToken(t *testing.T) {

	const prefix = "abc"

	token, err := Generate(prefix, Separator, RandomBytesLen)
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}

	// flip the last character of the code, which must invalidate the checksum
	tampered := token[:len(token)-1] + flipChar(token[len(token)-1])

	if IsChecksumOK(prefix, Separator, tampered) {
		t.Fatalf("expected tampered token %q to fail checksum validation", tampered)
	}
}

func flipChar(c byte) string {
	if c == 'a' {
		return "b"
	}
	return "a"
}

func TestIsChecksumOK_TableDriven(t *testing.T) {

	const (
		prefix    = "abc"
		separator = Separator
	)

	validToken, err := Generate(prefix, separator, RandomBytesLen)
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name      string
		prefix    string
		separator string
		token     string
		want      bool
	}{
		{
			name:      "valid token",
			prefix:    prefix,
			separator: separator,
			token:     validToken,
			want:      true,
		},
		{
			name:      "wrong prefix",
			prefix:    "xyz",
			separator: separator,
			token:     validToken,
			want:      false,
		},
		{
			name:      "wrong separator",
			prefix:    prefix,
			separator: "-",
			token:     validToken,
			want:      false,
		},
		{
			name:      "empty prefix and separator against valid token",
			prefix:    "",
			separator: "",
			token:     validToken,
			want:      false,
		},
		{
			name:      "empty token",
			prefix:    prefix,
			separator: separator,
			token:     "",
			want:      false,
		},
		{
			name:      "token shorter than prefix and separator",
			prefix:    prefix,
			separator: separator,
			token:     "ab",
			want:      false,
		},
		{
			name:      "token equal to prefix and separator, no code",
			prefix:    prefix,
			separator: separator,
			token:     prefix + separator,
			want:      false,
		},
		{
			name:      "truncated code shorter than checksum",
			prefix:    prefix,
			separator: separator,
			token:     prefix + separator + "1",
			want:      false,
		},
		{
			name:      "code truncated mid-checksum",
			prefix:    prefix,
			separator: separator,
			token:     validToken[:len(validToken)-2],
			want:      false,
		},
		{
			name:      "extra separator inside the code",
			prefix:    prefix,
			separator: separator,
			token:     validToken + separator + "extra",
			want:      false,
		},
		{
			name:      "invalid base62 characters in code",
			prefix:    prefix,
			separator: separator,
			token:     prefix + separator + "!!!not-base62!!!",
			want:      false,
		},
		{
			name:      "extremely long garbage token",
			prefix:    prefix,
			separator: separator,
			token:     prefix + separator + strings.Repeat("z", 10000),
			want:      false,
		},
		{
			name:      "all-empty prefix, separator, and token",
			prefix:    "",
			separator: "",
			token:     "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("IsChecksumOK panicked: %v", r)
				}
			}()
			if got := IsChecksumOK(tt.prefix, tt.separator, tt.token); got != tt.want {
				t.Errorf("IsChecksumOK(%q, %q, %q) = %v, want %v", tt.prefix, tt.separator, tt.token, got, tt.want)
			}
		})
	}
}

func TestIsChecksumOK_EmptyPrefixAndSeparator(t *testing.T) {

	token, err := Generate("", "", RandomBytesLen)
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}

	if !IsChecksumOK("", "", token) {
		t.Fatalf("expected valid checksum for token %q generated with empty prefix and separator", token)
	}
}

// TestIsChecksumOK_PrefixSeparatorConcatenationOnlyMatters documents that only the
// concatenation prefix+separator is meaningful: the boundary between the two arguments
// does not need to match between Generate and IsChecksumOK, and either may be empty.
func TestIsChecksumOK_PrefixSeparatorConcatenationOnlyMatters(t *testing.T) {

	token, err := Generate("ab", "c", RandomBytesLen)
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}

	splits := []struct{ prefix, separator string }{
		{"ab", "c"},
		{"abc", ""},
		{"", "abc"},
		{"a", "bc"},
	}
	for _, s := range splits {
		if !IsChecksumOK(s.prefix, s.separator, token) {
			t.Errorf("IsChecksumOK(%q, %q, token) = false, want true (same concatenation %q)", s.prefix, s.separator, s.prefix+s.separator)
		}
	}
}

// TestIsChecksumOK_RejectsNonCanonicalEncoding is a regression test for a finding surfaced
// by FuzzIsChecksumOK: base62's bit-packing encoding is not canonical, so a truncated
// variant of a valid token's body can decode to the exact same payload bytes as the
// original. IsChecksumOK must reject such a variant even though its checksum, once
// decoded, matches — only the exact canonical encoding of a payload is accepted.
func TestIsChecksumOK_RejectsNonCanonicalEncoding(t *testing.T) {

	const (
		prefix    = "abc"
		separator = Separator
	)

	fixedRandBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	crc := genCRC32(append([]byte(prefix+separator), fixedRandBytes...))
	payload := append(append([]byte{}, fixedRandBytes...), crc...)
	canonicalToken := prefix + separator + base62.EncodeToString(payload)

	// the original, canonical token must remain valid
	if !IsChecksumOK(prefix, separator, canonicalToken) {
		t.Fatalf("expected canonical token %q to be valid", canonicalToken)
	}

	// a truncated body that base62-decodes to the identical payload bytes must be
	// rejected, even though its checksum (once decoded) matches
	truncated := canonicalToken[:len(canonicalToken)-1]
	decodedTruncated, err := base62.DecodeString(truncated[len(prefix)+len(separator):])
	if nil != err {
		t.Fatalf("unexpected decode error for truncated body: %v", err)
	}
	if !bytes.Equal(decodedTruncated, payload) {
		t.Skip("truncated body no longer decodes to the identical payload under this base62 version; canonical-encoding regression scenario not reproduced")
	}
	if IsChecksumOK(prefix, separator, truncated) {
		t.Fatalf("expected non-canonical truncated token %q to be rejected", truncated)
	}
}

// TestIsChecksumOK_RejectsExtendedEncoding ensures a token body with extra trailing base62
// characters appended is rejected, whether or not the appended characters happen to still
// decode/checksum successfully.
func TestIsChecksumOK_RejectsExtendedEncoding(t *testing.T) {

	const (
		prefix    = "abc"
		separator = Separator
	)

	token, err := Generate(prefix, separator, RandomBytesLen)
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}

	extended := token + "1"
	if IsChecksumOK(prefix, separator, extended) {
		t.Fatalf("expected extended token %q to be rejected", extended)
	}
}
