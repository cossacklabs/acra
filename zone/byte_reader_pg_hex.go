/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package zone

import (
	"encoding/hex"
	"errors"
)

// ErrFakeDBByte error for wrong database byte format
var ErrFakeDBByte = errors.New("fake db format byte")

// PgHexByteReader reads hexadecimal bytes from binary input
type PgHexByteReader struct {
	currentIndex byte
	buffer       [2]byte
}

// NewPgHexByteReader returns new PgHexByteReader
func NewPgHexByteReader() *PgHexByteReader {
	return &PgHexByteReader{currentIndex: 0}
}

// Reset current reader index
func (reader *PgHexByteReader) Reset() {
	reader.currentIndex = 0
}

// GetBuffered returns bytes from buffer to currentIndex
func (reader *PgHexByteReader) GetBuffered() []byte {
	return reader.buffer[:reader.currentIndex]
}

func (reader *PgHexByteReader) reset() {
	reader.currentIndex = 0
}

func (reader *PgHexByteReader) returnError() (bool, byte, error) {
	reader.reset()
	return false, 0, ErrFakeDBByte
}

// ReadByte reads c and returns the bytes represented by the hexadecimal string
func (reader *PgHexByteReader) ReadByte(c byte) (bool, byte, error) {
	// 0-9 == 48-57
	// a-f == 65-70
	// A-F == 97-102
	if c < 48 || (c > 57 && c < 65) || (c > 70 && c < 97) || c > 102 {
		return reader.returnError()
	}
	reader.buffer[reader.currentIndex] = c
	if reader.currentIndex == 1 {
		decoded, err := hex.DecodeString(string(reader.buffer[:]))
		if err != nil {
			return reader.returnError()
		}
		reader.reset()
		return true, decoded[0], nil
	}
	reader.currentIndex++
	return false, 0, nil
}
