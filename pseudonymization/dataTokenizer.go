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

package pseudonymization

import (
	"github.com/cossacklabs/acra/encryptor/config"
	"strconv"

	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/sirupsen/logrus"
)

// DataTokenizer tokenizes and detokenizes data buffers.
type DataTokenizer struct {
	tokenizer common.Pseudoanonymizer
}

// NewDataTokenizer makes a new data buffer tokenizer based on provided pseudoanonymizer.
func NewDataTokenizer(tokenizer common.Pseudoanonymizer) (*DataTokenizer, error) {
	return &DataTokenizer{tokenizer}, nil
}

// Tokenize the data in given context with provided settings.
func (t *DataTokenizer) Tokenize(data []byte, context common.TokenContext, setting config.ColumnEncryptionSetting) ([]byte, error) {
	anonymize := t.tokenizer.Anonymize
	if setting.IsConsistentTokenization() {
		anonymize = t.tokenizer.AnonymizeConsistently
	}

	logrus.WithFields(logrus.Fields{"column": setting.ColumnName(), "client_id": string(context.ClientID), "zone_id": string(context.ZoneID)}).Debugln("Tokenize with DataTokenizer")
	tokenType := setting.GetTokenType()
	switch tokenType {
	case common.TokenType_Int32:
		i, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return nil, err
		}
		newVal, err := anonymize(int32(i), context, common.TokenType_Int32)
		if err != nil {
			return nil, err
		}
		return []byte(strconv.FormatInt(int64(newVal.(int32)), 10)), nil

	case common.TokenType_Int64:
		i, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return nil, err
		}
		newVal, err := anonymize(i, context, common.TokenType_Int64)
		if err != nil {
			return nil, err
		}
		return []byte(strconv.FormatInt(newVal.(int64), 10)), nil

	case common.TokenType_String:
		newVal, err := anonymize(string(data), context, common.TokenType_String)
		if err != nil {
			return nil, err
		}
		return []byte(newVal.(string)), nil

	case common.TokenType_Bytes:
		newVal, err := anonymize(data, context, common.TokenType_Bytes)
		if err != nil {
			return nil, err
		}
		return newVal.([]byte), nil

	case common.TokenType_Email:
		newVal, err := anonymize(common.Email(data), context, common.TokenType_Email)
		if err != nil {
			return nil, err
		}
		return []byte(newVal.(common.Email)), nil

	default:
		logrus.WithField("type", tokenType).Debugln("Unknown token type")
		return nil, ErrDataTypeMismatch
	}
}

// Detokenize the data in given context with provided settings.
func (t *DataTokenizer) Detokenize(data []byte, context common.TokenContext, setting config.ColumnEncryptionSetting) ([]byte, error) {
	logrus.WithFields(logrus.Fields{"column": setting.ColumnName(), "client_id": string(context.ClientID), "zone_id": string(context.ZoneID)}).Debugln("Detokenize with DataTokenizer")
	tokenType := setting.GetTokenType()
	switch tokenType {
	case common.TokenType_Int32:
		i, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return nil, err
		}
		newVal, err := t.tokenizer.Deanonymize(int32(i), context, common.TokenType_Int32)
		if err != nil {
			return nil, err
		}
		return []byte(strconv.FormatInt(int64(newVal.(int32)), 10)), nil

	case common.TokenType_Int64:
		i, err := strconv.ParseInt(string(data), 10, 64)
		if err != nil {
			return nil, err
		}
		newVal, err := t.tokenizer.Deanonymize(i, context, common.TokenType_Int64)
		if err != nil {
			return nil, err
		}
		return []byte(strconv.FormatInt(newVal.(int64), 10)), nil

	case common.TokenType_String:
		newVal, err := t.tokenizer.Deanonymize(string(data), context, common.TokenType_String)
		if err != nil {
			return nil, err
		}
		return []byte(newVal.(string)), nil

	case common.TokenType_Bytes:
		newVal, err := t.tokenizer.Deanonymize(data, context, common.TokenType_Bytes)
		if err != nil {
			return nil, err
		}
		return newVal.([]byte), nil

	case common.TokenType_Email:
		newVal, err := t.tokenizer.Deanonymize(common.Email(data), context, common.TokenType_Email)
		if err != nil {
			return nil, err
		}
		return []byte(newVal.(common.Email)), nil

	default:
		logrus.WithField("type", tokenType).Debugln("Unknown token type")
		return nil, ErrDataTypeMismatch
	}
}
