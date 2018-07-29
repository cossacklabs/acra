package mysql

import (
	"errors"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"io"
)

// ErrMalformPacket if packet parsing failed
var ErrMalformPacket = errors.New("Malform packet error")

// LengthEncodedInt https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
func LengthEncodedInt(data []byte) (num uint64, isNull bool, n int, err error) {
	if len(data) == 0 {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).Errorln("Can't get length encoded int, data length == 0")
		return uint64(0), false, 0, ErrMalformPacket
	}
	switch data[0] {

	// 251: NULL
	case 0xfb:
		n = 1
		isNull = true
		return

		// 252: value of following 2
	case 0xfc:
		if len(data) < 3 {
			return uint64(0), false, 0, ErrMalformPacket
		}
		num = uint64(data[1]) | uint64(data[2])<<8
		n = 3
		return

		// 253: value of following 3
	case 0xfd:
		if len(data) < 4 {
			return uint64(0), false, 0, ErrMalformPacket
		}
		num = uint64(data[1]) | uint64(data[2])<<8 | uint64(data[3])<<16
		n = 4
		return

		// 254: value of following 8
	case 0xfe:
		if len(data) < 9 {
			return uint64(0), false, 0, ErrMalformPacket
		}
		num = uint64(data[1]) | uint64(data[2])<<8 | uint64(data[3])<<16 |
			uint64(data[4])<<24 | uint64(data[5])<<32 | uint64(data[6])<<40 |
			uint64(data[7])<<48 | uint64(data[8])<<56
		n = 9
		return
	}

	// 0-250: value of first byte
	num = uint64(data[0])
	n = 1
	return
}

// LengthEncodedString https://dev.mysql.com/doc/internals/en/string.html#packet-Protocol::LengthEncodedString
func LengthEncodedString(data []byte) ([]byte, bool, int, error) {
	// Get length
	num, isNull, n, err := LengthEncodedInt(data)
	if num < 1 {
		return nil, isNull, n, err
	}

	n += int(num)

	// Check data length
	if len(data) >= n {
		return data[n-int(num) : n], false, n, nil
	}
	return nil, false, n, io.EOF
}

// SkipLengthEncodedString https://dev.mysql.com/doc/internals/en/string.html#packet-Protocol::LengthEncodedString
func SkipLengthEncodedString(data []byte) (int, error) {
	num, _, n, err := LengthEncodedInt(data)
	if err != nil {
		return 0, err
	}
	if num < 1 {
		return n, nil
	}

	n += int(num)

	if len(data) >= n {
		return n, nil
	}
	return n, io.EOF
}

// PutLengthEncodedInt https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
func PutLengthEncodedInt(n uint64) []byte {
	switch {
	case n <= 250:
		return []byte{byte(n)}

	case n <= 0xffff:
		return []byte{0xfc, byte(n), byte(n >> 8)}

	case n <= 0xffffff:
		return []byte{0xfd, byte(n), byte(n >> 8), byte(n >> 16)}

	case n <= 0xffffffffffffffff:
		return []byte{0xfe, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24),
			byte(n >> 32), byte(n >> 40), byte(n >> 48), byte(n >> 56)}
	}
	return nil
}

// PutLengthEncodedString https://dev.mysql.com/doc/internals/en/string.html#packet-Protocol::LengthEncodedString
func PutLengthEncodedString(b []byte) []byte {
	data := make([]byte, 0, len(b)+9)
	data = append(data, PutLengthEncodedInt(uint64(len(b)))...)
	data = append(data, b...)
	return data
}

// Uint16ToBytes returns bytes
func Uint16ToBytes(n uint16) []byte {
	return []byte{
		byte(n),
		byte(n >> 8),
	}
}

// Uint32ToBytes returns bytes
func Uint32ToBytes(n uint32) []byte {
	return []byte{
		byte(n),
		byte(n >> 8),
		byte(n >> 16),
		byte(n >> 24),
	}
}

// Uint64ToBytes returns bytes
func Uint64ToBytes(n uint64) []byte {
	return []byte{
		byte(n),
		byte(n >> 8),
		byte(n >> 16),
		byte(n >> 24),
		byte(n >> 32),
		byte(n >> 40),
		byte(n >> 48),
		byte(n >> 56),
	}
}
