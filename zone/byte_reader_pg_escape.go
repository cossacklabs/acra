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

// Package zone contains AcraStruct's zone matchers and readers.
// Zones are the way to cryptographically compartmentalise records in an already-encrypted environment.
// Zones rely on different private keys on the server side.
// Acra uses ZoneID identifier to identify, which key to use for decryption of a corresponding AcraStruct.
//
// The idea behind Zones is very simple: when we store sensitive data, it's frequently related
// to users / companies / some other binding entities. These entities could be described through
// some real-world identifiers, or (preferably) random identifiers, which have no computable relationship
// to the protected data.
//
// https://github.com/cossacklabs/acra/wiki/Zones
package zone

import (
	"github.com/cossacklabs/acra/utils"
	"strconv"
)

// PgEscapeByteReader reads escaped bytes from binary input
type PgEscapeByteReader struct {
	currentIndex byte
	buffer       [4]byte
}

// NewPgEscapeByteReader returns new PgEscapeByteReader
func NewPgEscapeByteReader() *PgEscapeByteReader {
	return &PgEscapeByteReader{currentIndex: 0}
}

// GetBuffered returns bytes from buffer to currentIndex
func (reader *PgEscapeByteReader) GetBuffered() []byte {
	return reader.buffer[:reader.currentIndex]
}

// Reset current reader index
func (reader *PgEscapeByteReader) Reset() {
	reader.currentIndex = 0
}

func (reader *PgEscapeByteReader) returnError() (bool, byte, error) {
	reader.Reset()
	return false, 0, ErrFakeDBByte
}

// ReadByte reads c and returns the bytes decoded from escaped format
func (reader *PgEscapeByteReader) ReadByte(c byte) (bool, byte, error) {
	if !utils.IsPrintableEscapeChar(c) {
		return reader.returnError()
	}
	if reader.currentIndex == 0 {
		if c == utils.SlashChar {
			reader.buffer[reader.currentIndex] = c
			reader.currentIndex++
			return false, 0, nil
		}
		reader.Reset()
		// value as is
		return true, c, nil
	} else if reader.currentIndex == 1 && c == utils.SlashChar {
		reader.Reset()
		// escaped slash, return as is
		return true, c, nil
	} else {
		// first octal value can be only 0-3
		if reader.currentIndex == 1 && (c < '0' || c > '3') {
			return reader.returnError()
		}
		// next values can be only 0-7
		if c < '0' || c > '7' {
			return reader.returnError()
		}
		reader.buffer[reader.currentIndex] = c
		reader.currentIndex++
		if reader.currentIndex == 4 {
			num, err := strconv.ParseInt(string(reader.buffer[1:4]), 8, 9)
			if err != nil {
				return reader.returnError()
			}
			reader.Reset()
			return true, byte(num), nil
		}
		return false, 0, nil
	}
}
