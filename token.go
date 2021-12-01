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

	bytes := append(randBytes, genCRC32(randBytes)...)
	//fmt.Println(bytes)

	return prefix + separator + base62.EncodeToString(bytes), nil
}

// IsChecksumOK - checks if a given input token has a valid checksum
func IsChecksumOK(prefix, separator, token string) (ok bool) {

	// strip prefix and separator from the token
	//remainder := token[len(prefix)+len(separator):]
	remainder, err := base62.DecodeString(token[len(prefix)+len(separator):])
	if nil != err {
		return // if an error is encountered, we return immediately, the token is definitely invalid
	}

	randBytesLen := len(remainder) - 6 // 6 bytes is used for checksum
	randBytes := remainder[:randBytesLen]
	givenChecksum := remainder[randBytesLen:] // last 6 bytes is used for checksum
	generatedChecksum := genCRC32(randBytes)  // last 6 bytes is used for checksum

	return bytes.Equal(givenChecksum, generatedChecksum)
}
