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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/sirupsen/logrus"
)

type anonymizer struct{}

// Anonymize return new random value according to specified dataType
func (a anonymizer) Anonymize(data interface{}, context common.TokenContext, dataType common.TokenType) (interface{}, error) {
	switch dataType {
	case common.TokenType_Int32:
		v, ok := data.(int32)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		return a.AnonymizeInt32(v, context)
	case common.TokenType_Int64:
		v, ok := data.(int64)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		return a.AnonymizeInt64(v, context)
	case common.TokenType_String:
		v, ok := data.(string)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		return a.AnonymizeStr(v, context)
	case common.TokenType_Email:
		v, ok := data.(common.Email)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		return a.AnonymizeEmail(v, context)
	case common.TokenType_Bytes:
		v, ok := data.([]byte)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		return a.AnonymizeBytes(v, context)
	default:
		return nil, common.ErrUnknownTokenType
	}
}

// AnonymizeInt32 return new random int32 value
func (a anonymizer) AnonymizeInt32(value int32, context common.TokenContext) (int32, error) {
	data := make([]byte, 32/8)
	if err := randomRead(data); err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(data)), nil
}

// AnonymizeInt64 return new random int64 value
func (a anonymizer) AnonymizeInt64(value int64, context common.TokenContext) (int64, error) {
	data := make([]byte, 64/8)
	if err := randomRead(data); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(data)), nil
}

// AnonymizeBytes return new random []byte value
func (a anonymizer) AnonymizeBytes(value []byte, context common.TokenContext) ([]byte, error) {
	data := make([]byte, len(value))
	if err := randomRead(data); err != nil {
		return nil, err
	}
	return data, nil
}

// AnonymizeStr return new random string value
func (a anonymizer) AnonymizeStr(value string, context common.TokenContext) (string, error) {
	data := make([]byte, len(value))
	if err := randomString(data); err != nil {
		return "", err
	}
	return string(data), nil
}

// AnonymizeEmail return new random Email value
func (a anonymizer) AnonymizeEmail(email common.Email, context common.TokenContext) (common.Email, error) {
	newEmail := make([]byte, len(email))
	if err := randomEmail(newEmail); err != nil {
		return "", err
	}
	return common.Email(newEmail), nil
}

// defaultDataGenerationLoopLimit define how much time will be re-generated value if it already exists in storage to generate unique
const defaultDataGenerationLoopLimit = 10

type pseudoanonymizer struct {
	dataGenerationLoopLimit int
	anonymizer              common.Anonymizer
	storage                 common.TokenStorage
	logger                  *logrus.Entry
}

// NewPseudoanonymizer create, initialize and return new instance of Pseudoanonymizer
func NewPseudoanonymizer(storage common.TokenStorage) (common.Pseudoanonymizer, error) {
	return &pseudoanonymizer{anonymizer: &anonymizer{}, storage: storage, dataGenerationLoopLimit: defaultDataGenerationLoopLimit, logger: logrus.NewEntry(logrus.StandardLogger())}, nil
}

// SetLogger setup logger which will be used by pseudoanonymizer internally
func (p *pseudoanonymizer) SetLogger(logger *logrus.Entry) *pseudoanonymizer {
	p.logger = logger
	return p
}

var dataIDDelim = []byte(`tokenizator hash delimiter`)

func (p *pseudoanonymizer) generateDataID(data []byte, context common.TokenContext, dataType common.TokenType) ([]byte, error) {
	h := sha256.New()
	h.Write(dataIDDelim)
	h.Write(data)
	if len(context.AdditionalContext) != 0 {
		// leave for backward compatibility when used zones
		h.Write([]byte(`zone`))
		h.Write(context.AdditionalContext)
	} else {
		h.Write([]byte(`client`))
		h.Write(context.ClientID)
	}
	h.Write(dataIDDelim)
	h.Write([]byte(strconv.Itoa(int(dataType))))
	key := h.Sum(nil)
	return key, nil
}

type newValueFunc func(interface{}, common.TokenContext) (interface{}, error)

// ErrGenerationRandomValue return when can't new random value which wasn't generated before and exceed count of tries to generate another value
var ErrGenerationRandomValue = errors.New("can't generate new random value, try count exceed")

func (p *pseudoanonymizer) generateKeyForHash(key []byte) []byte {
	return append([]byte(`h.`), key...)
}
func (p *pseudoanonymizer) generateKeyForToken(key []byte) []byte {
	return append([]byte(`t.`), key...)
}

// generateNewValue generate new random value, check that it wasn't saved in TokenStorage before and return new value or try to regenerate in a loop until
// generate new value or exceed try count
func (p *pseudoanonymizer) generateNewValue(f newValueFunc, value interface{}, context common.TokenContext, dataType common.TokenType) (interface{}, error) {
	for i := 0; i < p.dataGenerationLoopLimit; i++ {
		newValue, err := f(value, context)
		if err != nil {
			return 0, err
		}
		encodedNewValue, err := encodeToBytes(newValue, dataType)
		if err != nil {
			return nil, err
		}
		key, err := p.generateDataID(encodedNewValue, context, dataType)
		if err != nil {
			return nil, err
		}
		key = p.generateKeyForToken(key)
		encodedValue, err := encodeToBytes(value, dataType)
		if err != nil {
			return nil, err
		}
		value := &common.TokenValue{Value: encodedValue, Type: dataType}
		encodedData, err := common.EncodeTokenValue(value)
		if err != nil {
			return nil, err
		}
		if err := p.storage.Save(key, context, encodedData); err != nil {
			if err == common.ErrTokenExists {
				p.logger.WithFields(logrus.Fields{"iteration": i, "try_count": p.dataGenerationLoopLimit}).Debugln("Generated existing value, regenerate")
				continue
			}
			return 0, err
		}
		return newValue, nil
	}
	return nil, ErrGenerationRandomValue
}

// AnonymizeInt32 return new random int32 value
func (p *pseudoanonymizer) AnonymizeInt32(value int32, context common.TokenContext) (int32, error) {
	newVal, err := p.Anonymize(value, context, common.TokenType_Int32)
	if err != nil {
		return 0, err
	}
	return newVal.(int32), nil
}

// AnonymizeInt64 return new random int64 value
func (p *pseudoanonymizer) AnonymizeInt64(value int64, context common.TokenContext) (int64, error) {
	newVal, err := p.Anonymize(value, context, common.TokenType_Int64)
	if err != nil {
		return 0, err
	}
	return newVal.(int64), nil
}

// AnonymizeBytes return new random []byte value
func (p *pseudoanonymizer) AnonymizeBytes(value []byte, context common.TokenContext) ([]byte, error) {
	newVal, err := p.Anonymize(value, context, common.TokenType_Bytes)
	if err != nil {
		return nil, err
	}
	return newVal.([]byte), nil
}

// AnonymizeStr return new random string value
func (p *pseudoanonymizer) AnonymizeStr(value string, context common.TokenContext) (string, error) {
	newVal, err := p.Anonymize(value, context, common.TokenType_String)
	if err != nil {
		return "", err
	}
	return newVal.(string), nil
}

// AnonymizeEmail return new random Email value
func (p *pseudoanonymizer) AnonymizeEmail(email common.Email, context common.TokenContext) (common.Email, error) {
	newVal, err := p.Anonymize(email, context, common.TokenType_Email)
	if err != nil {
		return "", err
	}
	return newVal.(common.Email), nil
}

func bytesToGolangValue(data []byte, dataType common.TokenType) (interface{}, error) {
	switch dataType {
	case common.TokenType_Bytes:
		return data, nil
	case common.TokenType_String:
		return string(data), nil
	case common.TokenType_Email:
		return common.Email(data), nil
	case common.TokenType_Int32Str:
		v, err := decodeInt32(data)
		if err != nil {
			return nil, err
		}
		return strconv.FormatInt(int64(v), 10), nil
	case common.TokenType_Int64Str:
		v, err := decodeInt64(data)
		if err != nil {
			return nil, err
		}
		return strconv.FormatInt(v, 10), nil
	case common.TokenType_Int32:
		v, err := decodeInt32(data)
		if err != nil {
			return nil, err
		}
		return v, nil
	case common.TokenType_Int64:
		v, err := decodeInt64(data)
		if err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, common.ErrUnknownTokenType
	}
}

// ErrDataTypeMismatch used to show that required data type not equal to serializaed data type of stored value
var ErrDataTypeMismatch = errors.New("requested TokenType not match stored TokenType")

// Anonymize return new random value according to specified dataType
func (p *pseudoanonymizer) Anonymize(data interface{}, context common.TokenContext, dataType common.TokenType) (interface{}, error) {
	var f newValueFunc
	switch dataType {
	case common.TokenType_Int32:
		val, ok := data.(int32)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		f = func(v interface{}, context common.TokenContext) (interface{}, error) {
			return p.anonymizer.AnonymizeInt32(val, context)
		}
	case common.TokenType_Int64:
		val, ok := data.(int64)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		f = func(v interface{}, context common.TokenContext) (interface{}, error) {
			return p.anonymizer.AnonymizeInt64(val, context)
		}
	case common.TokenType_String:
		val, ok := data.(string)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		f = func(v interface{}, context common.TokenContext) (interface{}, error) {
			return p.anonymizer.AnonymizeStr(val, context)
		}
	case common.TokenType_Email:
		val, ok := data.(common.Email)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		f = func(v interface{}, context common.TokenContext) (interface{}, error) {
			return p.anonymizer.AnonymizeEmail(val, context)
		}
	case common.TokenType_Bytes:
		val, ok := data.([]byte)
		if !ok {
			return nil, common.ErrUnknownTokenType
		}
		f = func(v interface{}, context common.TokenContext) (interface{}, error) {
			return p.anonymizer.AnonymizeBytes(val, context)
		}
	default:
		return nil, common.ErrUnknownTokenType
	}
	newVal, err := p.generateNewValue(f, data, context, dataType)
	if err != nil {
		return 0, err
	}
	return newVal, nil
}

// AnonymizeConsistently return existing token for data if it was anonymized before or create new
func (p *pseudoanonymizer) AnonymizeConsistently(data interface{}, context common.TokenContext, dataType common.TokenType) (interface{}, error) {
	dataBytes, err := encodeToBytes(data, dataType)
	if err != nil {
		return nil, err
	}
	digest, err := p.generateDataID(dataBytes, context, dataType)
	if err != nil {
		return nil, err
	}
	digestKey := p.generateKeyForHash(digest)

	triedGetOnce := false
tryGetAgain:
	value, err := p.storage.Get(digestKey, context)
	if err == nil {
		return bytesToGolangValue(value, dataType)
	}
	newValue, err := p.Anonymize(data, context, dataType)
	if err != nil {
		return nil, err
	}
	encodedNewValue, err := encodeToBytes(newValue, dataType)
	if err != nil {
		return nil, err
	}
	if err := p.storage.Save(digestKey, context, encodedNewValue); err != nil {
		// A different instance may have received the same "data" and seen the "digestKey" as unused,
		// generated probably different "newValue" and called Save() for it before this instance.
		// If this happens and the token is reported as being in use, try the Get() check once more,
		// it should return the previously generated value now instead of ErrTokenNotFound.
		if err == common.ErrTokenExists && !triedGetOnce {
			p.logger.Debugln("Consistent tokenization collision detected, retrying once")
			triedGetOnce = true
			goto tryGetAgain
		}
		return nil, err
	}
	return newValue, nil
}

// Deanonymize return source value related to token
func (p *pseudoanonymizer) Deanonymize(token interface{}, context common.TokenContext, dataType common.TokenType) (interface{}, error) {
	tokenEncoded, err := encodeToBytes(token, dataType)
	if err != nil {
		return nil, err
	}
	key, err := p.generateDataID(tokenEncoded, context, dataType)
	if err != nil {
		return nil, err
	}
	key = p.generateKeyForToken(key)
	data, err := p.storage.Get(key, context)
	if err != nil {
		p.logger.Warningln("Token not found, return as is")
		return token, nil
	}
	tokenValue, err := common.TokenValueFromData(data)
	if err != nil {
		return nil, err
	}
	if tokenValue.Type != dataType {
		return nil, ErrDataTypeMismatch
	}
	return bytesToGolangValue(tokenValue.Value, dataType)
}
