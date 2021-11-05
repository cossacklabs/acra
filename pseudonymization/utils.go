/*
Copyright 2020, Cossack Labs Limited

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

package pseudonymization

import (
	"encoding/binary"
	"github.com/cossacklabs/acra/pseudonymization/common"
)

func encodeInt32(v int32) []byte {
	d := make([]byte, 4)
	binary.LittleEndian.PutUint32(d, uint32(v))
	return d
}
func encodeInt64(v int64) []byte {
	d := make([]byte, 8)
	binary.LittleEndian.PutUint64(d, uint64(v))
	return d
}

func decodeInt32(data []byte) (int32, error) {
	return int32(binary.LittleEndian.Uint32(data)), nil
}

func decodeInt64(data []byte) (int64, error) {
	return int64(binary.LittleEndian.Uint64(data)), nil
}

func encodeToBytes(data interface{}, dataType common.TokenType) ([]byte, error) {
	var v []byte
	switch value := data.(type) {
	case int32:
		if dataType != common.TokenType_Int32 {
			return nil, ErrDataTypeMismatch
		}
		v = encodeInt32(value)
	case int64:
		if dataType != common.TokenType_Int64 {
			return nil, ErrDataTypeMismatch
		}
		v = encodeInt64(value)
	case common.Email:
		if dataType != common.TokenType_Email {
			return nil, ErrDataTypeMismatch
		}
		v = []byte(value)
	case []byte:
		if dataType != common.TokenType_Bytes {
			return nil, ErrDataTypeMismatch
		}
		v = value
	case string:
		if dataType != common.TokenType_String {
			return nil, ErrDataTypeMismatch
		}
		v = []byte(value)
	default:
		return nil, common.ErrUnknownTokenType
	}
	return v, nil
}
