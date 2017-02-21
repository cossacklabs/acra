// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package zone

import (
	"encoding/hex"
	"errors"
)

var FAKE_DB_BYTE = errors.New("Fake db format byte")

type PgHexByteReader struct {
	currentIndex byte
	buffer       [2]byte
}

func NewPgHexByteReader() *PgHexByteReader {
	return &PgHexByteReader{currentIndex: 0}
}

func (reader *PgHexByteReader) Reset() {
	reader.currentIndex = 0
}

func (reader *PgHexByteReader) GetBuffered() []byte {
	return reader.buffer[:reader.currentIndex]
}

func (reader *PgHexByteReader) reset() {
	reader.currentIndex = 0
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
