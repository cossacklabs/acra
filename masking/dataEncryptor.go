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

package masking

import (
	"errors"

	encryptor "github.com/cossacklabs/acra/encryptor/base"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/keystore"
)

// DataEncryptor performs partial encryption of plaintext in the cell
type DataEncryptor struct {
	acrawriterEncryptor encryptor.DataEncryptor
	keystore            keystore.DecryptionKeyStore
	decryptor           base.DecryptProcessor
}

// NewMaskingDataEncryptor return new DataEncryptor
func NewMaskingDataEncryptor(keystore keystore.DecryptionKeyStore, dataEncryptor encryptor.DataEncryptor) (*DataEncryptor, error) {
	return &DataEncryptor{dataEncryptor, keystore, base.DecryptProcessor{}}, nil
}

// EncryptWithClientID mask data according to setting
func (e *DataEncryptor) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	return e.encryptByFunction(clientID, data, setting, e.acrawriterEncryptor.EncryptWithClientID)
}

type encryptionFunction func([]byte, []byte, config.ColumnEncryptionSetting) ([]byte, error)

func (e *DataEncryptor) encryptByFunction(context, data []byte, settingCE config.ColumnEncryptionSetting, encryptionFunc encryptionFunction) ([]byte, error) {
	setting, ok := settingCE.(config.ColumnEncryptionSetting)
	if !ok {
		return nil, errors.New("can't cast column encryption settings")
	}
	if setting.GetMaskingPattern() != "" {
		partialPlaintextLen := setting.GetPartialPlaintextLen()
		if partialPlaintextLen >= len(data) {
			// two variants are possible in such case:
			// to encrypt all data or to left all data in plaintext.
			// Seems encrypt data is better
			return encryptionFunc(context, data, setting)
		}
		var result []byte
		if setting.IsEndMasking() {
			partialPlaintext := data[0:partialPlaintextLen]
			acrastruct, err := encryptionFunc(context, data[partialPlaintextLen:], setting)
			if err != nil {
				return nil, err
			}
			result = append(partialPlaintext, acrastruct...)
		} else {
			partialPlaintext := data[len(data)-partialPlaintextLen:]
			acrastruct, err := encryptionFunc(context, data[0:len(data)-partialPlaintextLen], setting)
			if err != nil {
				return nil, err
			}
			result = append(acrastruct, partialPlaintext...)
		}
		return result, nil
	}
	return data, nil
}
