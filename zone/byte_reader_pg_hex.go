package zone

import (
	"encoding/hex"
	"errors"
)

var FAKE_DB_BYTE = errors.New("Fake db format byte")

type PgHexByteReader struct {
	current_index byte
	buffer        [2]byte
}

func NewPgHexByteReader() *PgHexByteReader {
	return &PgHexByteReader{current_index: 0}
}

func (reader *PgHexByteReader) Reset() {
	reader.current_index = 0
}

func (reader *PgHexByteReader) GetBuffered() []byte {
	return reader.buffer[:reader.current_index]
}

func (reader *PgHexByteReader) reset() {
	reader.current_index = 0
}

func (reader *PgHexByteReader) returnError() (bool, byte, error) {
	reader.reset()
	return false, 0, FAKE_DB_BYTE
}

func (reader *PgHexByteReader) ReadByte(c byte) (bool, byte, error) {
	// 0-9 == 48-57
	// a-f == 65-70
	// A-F == 97-102
	if c < 48 || (c > 57 && c < 65) || (c > 70 && c < 97) || c > 102 {
		return reader.returnError()
	}
	reader.buffer[reader.current_index] = c
	if reader.current_index == 1 {
		decoded, err := hex.DecodeString(string(reader.buffer[:]))
		if err != nil {
			return reader.returnError()
		}
		reader.reset()
		return true, decoded[0], nil
	} else {
		reader.current_index++
		return false, 0, nil
	}
}
