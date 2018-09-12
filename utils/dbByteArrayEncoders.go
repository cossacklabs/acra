/*
Copyright 2018, Cossack Labs Limited

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

package utils

import (
	"encoding/hex"
	"fmt"
	"github.com/lib/pq"
	"strconv"
	"strings"
)

func encodeToOctal(from, to []byte) {
	to = to[:0]
	for _, c := range from {
		if IsPrintableEscapeChar(c) {
			if c == SlashChar {
				to = append(to, []byte{SlashChar, SlashChar}...)
			} else {
				to = append(to, c)
			}
		} else {
			to = append(to, SlashChar)
			octal := strconv.FormatInt(int64(c), 8)
			switch len(octal) {
			case 3:
				to = append(to, []byte(octal)...)
			case 2:
				to = append(to, '0', octal[0], octal[1])

			case 1:
				to = append(to, '0', '0', octal[0])
			}
		}
	}
}

// EncodeToOctal returns octal representation on bytes
// each byte has 4 bytes, filled with leading 0's is needed
func EncodeToOctal(from []byte) []byte {
	// count output size
	outputLength := 0
	for _, c := range from {
		if IsPrintableEscapeChar(c) {
			if c == SlashChar {
				outputLength += 2
			} else {
				outputLength++
			}
		} else {
			outputLength += 4
		}
	}
	buffer := make([]byte, outputLength)
	encodeToOctal(from, buffer)
	return buffer
}

// QuoteValue returns name in quotes, if name contains quotes, doubles them
func QuoteValue(name string) string {
	end := strings.IndexRune(name, 0)
	if end > -1 {
		name = name[:end]
	}
	return `'` + strings.Replace(name, `'`, `''`, -1) + `'`
}

// BinaryEncoder encodes binary to string
type BinaryEncoder interface {
	EncodeToString([]byte) string
	Encode([]byte) interface{}
}

// MysqlEncoder encodes MySQL packets
type MysqlEncoder struct{}

// EncodeToString bytes to Hex supported by MySQL
func (e *MysqlEncoder) EncodeToString(data []byte) string {
	return fmt.Sprintf("X'%s'", hex.EncodeToString(data))
}

// Encode return data as is
func (encoder *MysqlEncoder) Encode(data []byte) interface{} {
	return data
}

// EscapeEncoder for Postgres
type EscapeEncoder struct{}

// EncodeToString bytes to Postgres Octal format
func (e *EscapeEncoder) EncodeToString(data []byte) string {
	return QuoteValue(string(EncodeToOctal(data)))
}

// Encode return data as is
func (e *EscapeEncoder) Encode(data []byte) interface{} {
	return data
}

// HexEncoder for hex
type HexEncoder struct{}

// EncodeToString bytes to Hex
func (*HexEncoder) EncodeToString(data []byte) string {
	return fmt.Sprintf("E'\\\\x%s'", hex.EncodeToString(data))
}

// Encode return data as is
func (e *HexEncoder) Encode(data []byte) interface{} {
	return data
}

// PqEncoder wrap array with pq.Array
type PqEncoder struct{}

// EncodeToString use HexEncoder.EncodeToString
func (*PqEncoder) EncodeToString(data []byte) string {
	return (&HexEncoder{}).EncodeToString(data)
}

// Encode wrap data with pq.Array
func (*PqEncoder) Encode(data []byte) interface{} {
	return pq.Array(data)
}
