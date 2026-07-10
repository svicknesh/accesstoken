package accesstoken

import (
	"hash/crc32"

	"github.com/jxskiss/base62"
)

const (
	// tblCastagnoli is Castagnoli's CRC-32 polynomial, used in iSCSI.
	// It has better error detection characteristics than the more common IEEE polynomial.
	// https://dx.doi.org/10.1109/26.231911
	tblCastagnoli = 0x82f63b78

	// checksumByteLen is the fixed encoded length, in bytes, of the checksum produced by
	// genCRC32. A 32-bit value base62-encodes to at most 6 bytes, so the result is
	// zero-padded up to that length.
	checksumByteLen = 6
)

// genCRC32 computes a non-cryptographic CRC-32 (Castagnoli) checksum of input, encoded as
// checksumByteLen base62 bytes, left-padded with zero bytes as needed. This checksum
// detects accidental corruption only; it provides no tamper resistance or authenticity
// guarantee, since it involves no secret key.
func genCRC32(input []byte) (checksum []byte) {

	crc32q := crc32.MakeTable(tblCastagnoli)

	checksum = base62.FormatUint(uint64(crc32.Checksum(input, crc32q)))

	// left-pad with zero bytes so the result is always checksumByteLen bytes long
	for i := len(checksum); i < checksumByteLen; i++ {
		checksum = append([]byte{0}, checksum...)
	}

	return
}
