/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"errors"
	"github.com/cossacklabs/acra/encryptor/config/common"

	"github.com/golang/protobuf/proto"
)

var supportedTokenTypes = map[TokenType]bool{
	TokenType_Int32:  true,
	TokenType_Int64:  true,
	TokenType_String: true,
	TokenType_Bytes:  true,
	TokenType_Email:  true,
}

// ToConfigString converts value to string used in encryptor_config
func (x TokenType) ToConfigString() (val string, err error) {
	err = ErrUnknownTokenType
	switch x {
	case TokenType_Int32:
		return "int32", nil
	case TokenType_Int64:
		return "int64", nil
	case TokenType_String:
		return "str", nil
	case TokenType_Bytes:
		return "bytes", nil
	case TokenType_Email:
		return "email", nil
	}
	return
}

// ToEncryptedDataType converts value to appropriate EncryptedType
func (x TokenType) ToEncryptedDataType() common.EncryptedType {
	switch x {
	case TokenType_Int32:
		return common.EncryptedType_Int32
	case TokenType_Int64:
		return common.EncryptedType_Int64
	case TokenType_String, TokenType_Email:
		return common.EncryptedType_String
	case TokenType_Bytes:
		return common.EncryptedType_Bytes
	}
	return common.EncryptedType_Unknown
}

// Validation errors
var (
	ErrUnknownTokenType     = errors.New("unknown token type")
	ErrUnsupportedTokenType = errors.New("token type not supported")
)

// ValidateTokenType return true if value is supported TokenType
func ValidateTokenType(value TokenType) error {
	supported, ok := supportedTokenTypes[value]
	if !ok {
		return ErrUnknownTokenType
	}
	if !supported {
		return ErrUnsupportedTokenType
	}
	return nil
}

// NormalizeTokenType checks the token type and replaces it with the default value if the type is not supported or invalid.
func NormalizeTokenType(value TokenType, defaultType TokenType) TokenType {
	supported, ok := supportedTokenTypes[value]
	if !ok || !supported {
		return defaultType
	}
	return value
}

// EncodeTokenValue serializes token value into bytes.
func EncodeTokenValue(value *TokenValue) ([]byte, error) {
	return proto.Marshal(value)
}

// TokenValueFromData deserializes token value from bytes.
func TokenValueFromData(data []byte) (*TokenValue, error) {
	value := new(TokenValue)
	err := proto.Unmarshal(data, value)
	if err != nil {
		return nil, err
	}
	return value, nil
}
