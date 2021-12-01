package accesstoken

import (
	"hash/crc32"

	"github.com/jxskiss/base62"
)

const (
	// IEEE is by far and away the most common CRC-32 polynomial.
	// Used by ethernet (IEEE 802.3), v.42, fddi, gzip, zip, png, ...
	//IEEE = 0xedb88320
	// Castagnoli's polynomial, used in iSCSI.
	// Has better error detection characteristics than IEEE.
	// https://dx.doi.org/10.1109/26.231911
	tblCastagnoli = 0x82f63b78
	// Koopman's polynomial.
	// Also has better error detection characteristics than IEEE.
	// https://dx.doi.org/10.1109/DSN.2002.1028931
	//Koopman = 0xeb31d82e
)

// genCRC32 - generates CRC based on given input
func genCRC32(input []byte) (checksum []byte) {

	crc32q := crc32.MakeTable(tblCastagnoli)
	//fmt.Printf("%08x\n", crc32.Checksum([]byte(input), crc32q))

	checksum = base62.FormatUint(uint64(crc32.Checksum(input, crc32q)))

	// we append 0 to make sure we get 6 bytes for the checksum
	for i := len(checksum); i < 6; i++ {
		checksum = append([]byte{0}, checksum...)
	}

	return
}
