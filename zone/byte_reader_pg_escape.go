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
	"github.com/cossacklabs/acra/utils"
	"strconv"
)

type PgEscapeByteReader struct {
	current_index byte
	buffer        [4]byte
}

func NewPgEscapeByteReader() *PgEscapeByteReader {
	return &PgEscapeByteReader{current_index: 0}
}

func (reader *PgEscapeByteReader) GetBuffered() []byte {
	return reader.buffer[:reader.current_index]
}

func (reader *PgEscapeByteReader) Reset() {
	reader.current_index = 0
}

func (reader *PgEscapeByteReader) returnError() (bool, byte, error) {
	reader.Reset()
	return false, 0, FAKE_DB_BYTE
}

func (reader *PgEscapeByteReader) ReadByte(c byte) (bool, byte, error) {
	if !utils.IsPrintableEscapeChar(c) {
		return reader.returnError()
	}
	if reader.current_index == 0 {
		if c == utils.SLASH_CHAR {
			reader.buffer[reader.current_index] = c
			reader.current_index++
			return false, 0, nil
		} else {
			reader.Reset()
			// value as is
			return true, c, nil
		}
	} else if reader.current_index == 1 && c == utils.SLASH_CHAR {
		reader.Reset()
		// escaped slash, return as is
		return true, c, nil
	} else {
		// first octal value can be only 0-3
		if reader.current_index == 1 && (c < '0' || c > '3') {
			return reader.returnError()
		}
		// next values can be only 0-7
		if c < '0' || c > '7' {
			return reader.returnError()
		}
		reader.buffer[reader.current_index] = c
		reader.current_index++
		if reader.current_index == 4 {
			num, err := strconv.ParseInt(string(reader.buffer[1:4]), 8, 9)
			if err != nil {
				return reader.returnError()
			}
			reader.Reset()
			return true, byte(num), nil
		} else {
			return false, 0, nil
		}
	}
}
