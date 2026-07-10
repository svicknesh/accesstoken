package accesstoken

import (
	"testing"

	"github.com/jxskiss/base62"
)

// FuzzIsChecksumOK asserts that IsChecksumOK never panics on arbitrary, attacker-controlled
// input, and that it only accepts the one known-valid reference token — not any alternate
// string that merely decodes to the same payload bytes.
//
// The reference token is built deterministically (not via Generate, which uses
// crypto/rand) so the invariant holds across fuzzing worker processes, which each
// re-run this function's setup independently. String equality is the correct invariant
// here: IsChecksumOK enforces canonical base62 encoding, so exactly one string is accepted
// per payload — truncated, extended, or otherwise aliased encodings of the same bytes
// (base62's bit-packing encoding is not canonical) must be rejected.
func FuzzIsChecksumOK(f *testing.F) {

	const (
		prefix    = "abc"
		separator = Separator
	)

	fixedRandBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	crc := genCRC32(append([]byte(prefix+separator), fixedRandBytes...))
	payload := append(append([]byte{}, fixedRandBytes...), crc...)
	validToken := prefix + separator + base62.EncodeToString(payload)

	seeds := []string{
		"",
		prefix,
		prefix + separator,
		validToken,
		validToken[:len(validToken)-1],
		validToken + "extra",
		"!!!not-base62!!!",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("IsChecksumOK panicked on input %q: %v", token, r)
			}
		}()

		ok := IsChecksumOK(prefix, separator, token)
		if ok && token != validToken {
			t.Fatalf("IsChecksumOK unexpectedly accepted non-canonical/forged token %q", token)
		}
	})
}
