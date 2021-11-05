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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"strings"
)

// EncodeToOctal escape string
// See https://www.postgresql.org/docs/current/static/datatype-binary.html#AEN5667
func EncodeToOctal(data []byte) []byte {
	res := make([]byte, 0, len(data))
	for _, c := range []byte(data) {
		if c == '\\' {
			res = append(res, '\\', '\\')
		} else if !IsPrintableEscapeChar(c) {
			// encode to octal \xxx format
			res = append(res, '\\', '0'+(c>>6), '0'+((c>>3)&7), '0'+(c&7))
		} else {
			res = append(res, c)
		}
	}
	return res
}

// ErrDecodeOctalString on incorrect decoding with DecodeOctal
var ErrDecodeOctalString = errors.New("can't decode escaped string")

// DecodeOctal escaped string
// See https://www.postgresql.org/docs/current/static/datatype-binary.html#AEN5667
func DecodeOctal(data []byte) ([]byte, error) {
	output := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if !IsPrintableEscapeChar(ch) {
			return nil, ErrDecodeOctalString
		}
		if ch != '\\' {
			output = append(output, ch)
			continue
		}
		if i >= len(data)-1 {
			logrus.Debugln("Encoded string incomplete")
			return nil, ErrDecodeOctalString
		}
		if data[i+1] == '\\' {
			output = append(output, '\\')
			i++
			continue
		}
		if i+3 >= len(data) {
			logrus.Debugln("Encoded string incomplete")
			return nil, ErrDecodeOctalString
		}
		b := byte(0)
		for j := 1; j <= 3; j++ {
			octDigit := data[i+j]
			if octDigit < '0' || octDigit > '7' {
				logrus.Debugln("Invalid bytea escape sequence")
				return nil, ErrDecodeOctalString
			}
			b = (b << 3) | (octDigit - '0')
		}
		output = append(output, b)
		i += 3
	}
	return output, nil
}

// DecodedData wrap binary data which should be encoded in final format after usage
type DecodedData struct {
	data       []byte
	encodeFunc func([]byte) []byte
}

// Data return binary data
func (d *DecodedData) Data() []byte {
	return d.data
}

// Set set binary data
func (d *DecodedData) Set(data []byte) {
	d.data = data
}

// Encoded return encoded binary data in final format according to encoding logic
func (d *DecodedData) Encoded() []byte {
	return d.encodeFunc(d.data)
}

func hexEncode(data []byte) []byte {
	output := make([]byte, 2+hex.EncodedLen(len(data)))
	copy(output[:2], []byte{'\\', 'x'})
	hex.Encode(output[2:], data)
	return output
}

func dryEncode(data []byte) []byte {
	return data
}

// WrapRawDataAsDecoded return DecodedData with Encode function which return data as is
func WrapRawDataAsDecoded(data []byte) *DecodedData {
	return &DecodedData{data: data, encodeFunc: dryEncode}
}

// DecodeEscaped with hex or octal encodings
func DecodeEscaped(data []byte) (*DecodedData, error) {
	if len(data) >= 2 && bytes.Equal(data[:2], []byte{'\\', 'x'}) {
		hexdata := data[2:]
		output := make([]byte, hex.DecodedLen(len(hexdata)))
		_, err := hex.Decode(output, hexdata)
		return &DecodedData{data: output, encodeFunc: hexEncode}, err
	}
	result, err := DecodeOctal(data)
	if err != nil {
		return &DecodedData{data: data, encodeFunc: dryEncode}, ErrDecodeOctalString
	}
	return &DecodedData{data: result, encodeFunc: EncodeToOctal}, nil
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
func (e *MysqlEncoder) Encode(data []byte) interface{} {
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
