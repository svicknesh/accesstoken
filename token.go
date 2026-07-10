// Package accesstoken generates and validates access tokens in the format
// prefix+separator+code, similar to the format used by GitHub. See the package README
// for the security properties and limitations of checksum validation.
package accesstoken

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/jxskiss/base62"
)

const (
	// Separator is the default separator used to distinguish the prefix from the generated code.
	Separator = "_"

	// RandomBytesLen is the default number of random bytes used to generate the code.
	RandomBytesLen = 32
)

// ErrInvalidRandBytesLen is returned by Generate when randBytesLen is not greater than zero.
var ErrInvalidRandBytesLen = errors.New("accesstoken: randBytesLen must be greater than zero")

// Generate creates an access token in the form prefix+separator+code, where code is a
// base62-encoded combination of randBytesLen cryptographically random bytes and a
// checksum. The checksum only detects accidental corruption of the token; it is not a
// cryptographic signature and does not prove the token was issued by a trusted system.
//
// prefix and separator may each be empty; only their concatenation, prefix+separator, is
// meaningful to Generate and IsChecksumOK — the two arguments do not need to agree on
// exactly where the boundary between prefix and separator falls, as long as the combined
// string matches between generation and validation.
func Generate(prefix, separator string, randBytesLen int) (output string, err error) {

	if randBytesLen <= 0 {
		err = ErrInvalidRandBytesLen
		return
	}

	randBytes := make([]byte, randBytesLen)
	_, err = rand.Read(randBytes)
	if nil != err {
		return
	}

	crc32Bytes := genCRC32(append([]byte(prefix+separator), randBytes...)) // append the prefix, separator & random bytes to generate CRC32

	return prefix + separator + base62.EncodeToString(append(randBytes, crc32Bytes...)), nil
}

// IsChecksumOK reports whether token has the given prefix and separator, whether its
// embedded checksum matches its embedded random bytes, and whether its base62 body is the
// canonical encoding of those bytes. It never panics: any malformed, truncated, extended,
// aliased, or otherwise invalid token yields false.
//
// The canonical-encoding check matters because base62's bit-packing encoding is not
// injective in reverse: some non-canonical strings (e.g. a truncated variant of a valid
// token) decode to the exact same bytes as the canonical one. Requiring the body to
// re-encode to itself ensures each decoded payload has exactly one accepted textual
// representation; it does not add cryptographic authentication, only encoding uniqueness.
//
// A true result only means the token is well-formed and was not accidentally corrupted.
// It is not proof of authenticity, issuance, authorization, or that the token has not been
// revoked or expired — callers must still perform a database/revocation lookup before
// trusting a token.
func IsChecksumOK(prefix, separator, token string) (ok bool) {

	prefixLen := len(prefix) + len(separator)
	if len(token) < prefixLen || token[:prefixLen] != prefix+separator {
		return false // token too short, or does not start with the expected prefix and separator
	}

	// strip prefix and separator from the token and base62 decode the random bytes + CRC32 checksum
	body := token[prefixLen:]
	remainder, err := base62.DecodeString(body)
	if nil != err {
		return // if an error is encountered, we return immediately, the token is definitely invalid
	}

	if len(remainder) < checksumByteLen {
		return false // too short to contain a checksum, definitely invalid
	}

	randBytesLen := len(remainder) - checksumByteLen // random bytes is the total length minus the checksum length
	randBytes := remainder[:randBytesLen]
	givenChecksum := remainder[randBytesLen:]                                     // last bytes are the checksum
	generatedChecksum := genCRC32(append([]byte(prefix+separator), randBytes...)) // generate the checksum using input prefix, separator and obtained random bytes

	if !bytes.Equal(givenChecksum, generatedChecksum) {
		return false
	}

	// reject non-canonical encodings of the same bytes (truncated, extended, or aliased
	// base62 bodies that happen to decode to a valid payload)
	canonicalBody := base62.EncodeToString(remainder)
	return canonicalBody == body
}
