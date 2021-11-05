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

package pseudonymization

import (
	configCE "github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/pseudonymization/common"
)

// TokenEncryptor adds hash prefix to AcraStruct generated with encryptor.AcrawriterDataEncryptor
type TokenEncryptor struct {
	tokenizer *DataTokenizer
}

// NewTokenEncryptor return new TokenEncryptor
func NewTokenEncryptor(tokenizer *DataTokenizer) (*TokenEncryptor, error) {
	return &TokenEncryptor{tokenizer}, nil
}

// EncryptWithZoneID tokenize data according to setting
func (e *TokenEncryptor) EncryptWithZoneID(zoneID, data []byte, setting configCE.ColumnEncryptionSetting) ([]byte, error) {
	if setting.IsTokenized() {
		tokenContext := common.TokenContext{ZoneID: zoneID}
		return e.tokenizer.Tokenize(data, tokenContext, setting)
	}
	return data, nil
}

// EncryptWithClientID tokenize data according to setting
func (e *TokenEncryptor) EncryptWithClientID(clientID, data []byte, setting configCE.ColumnEncryptionSetting) ([]byte, error) {
	if setting.IsTokenized() {
		tokenContext := common.TokenContext{ClientID: clientID}
		return e.tokenizer.Tokenize(data, tokenContext, setting)
	}
	return data, nil
}
