package mysql

import (
	"errors"
	"io"
)

var ErrMalformPacket = errors.New("Malform packet error")

func LengthEncodedInt(data []byte) (num uint64, isNull bool, n int) {
	switch data[0] {

	// 251: NULL
	case 0xfb:
		n = 1
		isNull = true
		return

		// 252: value of following 2
	case 0xfc:
		num = uint64(data[1]) | uint64(data[2])<<8
		n = 3
		return

		// 253: value of following 3
	case 0xfd:
		num = uint64(data[1]) | uint64(data[2])<<8 | uint64(data[3])<<16
		n = 4
		return

		// 254: value of following 8
	case 0xfe:
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

func LengthEncodedString(data []byte) ([]byte, bool, int, error) {
	// Get length
	num, isNull, n := LengthEncodedInt(data)
	if num < 1 {
		return nil, isNull, n, nil
	}

	n += int(num)

	// Check data length
	if len(data) >= n {
		return data[n-int(num) : n], false, n, nil
	}
	return nil, false, n, io.EOF
}

func SkipLengthEnodedString(data []byte) (int, error) {
	num, _, n := LengthEncodedInt(data)
	if num < 1 {
		return n, nil
	}

	n += int(num)

	if len(data) >= n {
		return n, nil
	}
	return n, io.EOF
}

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

func PutLengthEncodedString(b []byte) []byte {
	data := make([]byte, 0, len(b)+9)
	data = append(data, PutLengthEncodedInt(uint64(len(b)))...)
	data = append(data, b...)
	return data
}

func Uint16ToBytes(n uint16) []byte {
	return []byte{
		byte(n),
		byte(n >> 8),
	}
}

func Uint32ToBytes(n uint32) []byte {
	return []byte{
		byte(n),
		byte(n >> 8),
		byte(n >> 16),
		byte(n >> 24),
	}
}

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
