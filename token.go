package accesstoken

import (
	"bytes"
	"crypto/rand"

	"github.com/jxskiss/base62"
)

const (
	// Separator - default separator used for distinguishing prefix from the actual code
	Separator = "_"

	// RandomBytesLen = default random bytes to generate for the code
	RandomBytesLen = 32
)

// Generate - generate an access token based on the given input
func Generate(prefix, separator string, randBytesLen int) (output string, err error) {

	//output = prefix + separator + randString(32)

	randBytes := make([]byte, randBytesLen)
	_, err = rand.Read(randBytes)
	if nil != err {
		return
	}
	//fmt.Println(randBytes)

	crc32Bytes := genCRC32(append([]byte(prefix+separator), randBytes...)) // append the prefix, separator & random bytes to generate CRC32

	return prefix + separator + base62.EncodeToString(append(randBytes, crc32Bytes...)), nil
}

// IsChecksumOK - checks if a given input token has a valid checksum
func IsChecksumOK(prefix, separator, token string) (ok bool) {

	// strip prefix and separator from the token and base62 decode the random bytes + CRC32 checksum
	remainder, err := base62.DecodeString(token[len(prefix)+len(separator):])
	if nil != err {
		return // if an error is encountered, we return immediately, the token is definitely invalid
	}

	randBytesLen := len(remainder) - 6 // random bytes is the total length - 6 bytes which is used for checksum
	randBytes := remainder[:randBytesLen]
	givenChecksum := remainder[randBytesLen:]                                     // last 6 bytes is used for checksum
	generatedChecksum := genCRC32(append([]byte(prefix+separator), randBytes...)) // generate the checksum using input prefix, separator and obtained random bytes

	return bytes.Equal(givenChecksum, generatedChecksum)
}
