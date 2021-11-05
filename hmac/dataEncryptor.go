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

package hmac

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	estore "github.com/cossacklabs/acra/keystore"
	"github.com/sirupsen/logrus"
)

// SearchableDataEncryptor adds hash prefix to AcraStruct generated with encryptor.AcrawriterDataEncryptor
type SearchableDataEncryptor struct {
	dataEncryptor encryptor.DataEncryptor
	keystore      SearchableEncryptorKeystore
	decryptor     base.ExtendedDataProcessor
}

// SearchableEncryptorKeystore keystore interface used by SearchableAcrastructEncryptor
type SearchableEncryptorKeystore interface {
	estore.HmacKeyStore
	keystore.PrivateKeyStore
	keystore.PublicKeyStore
}

// NewSearchableEncryptor return new SearchableDataEncryptor
func NewSearchableEncryptor(keystore SearchableEncryptorKeystore, dataEncryptor encryptor.DataEncryptor, dataProcessor base.ExtendedDataProcessor) (*SearchableDataEncryptor, error) {
	return &SearchableDataEncryptor{dataEncryptor, keystore, dataProcessor}, nil
}

// EncryptWithZoneID proxy call to AcrawriterEncryptor
func (e *SearchableDataEncryptor) EncryptWithZoneID(zoneID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	return data, nil
}

//EncryptWithClientID add prefix with hmac to encrypted result from AcrawriterEncryptor
func (e *SearchableDataEncryptor) EncryptWithClientID(clientID, data []byte, settingCE config.ColumnEncryptionSetting) ([]byte, error) {
	setting, ok := settingCE.(config.ColumnEncryptionSetting)
	if ok && setting.IsSearchable() {
		logrus.Debugln("Encrypt with searching")
		key, err := e.keystore.GetHMACSecretKey(clientID)
		if err != nil {
			return nil, err
		}
		var encryptedData, hash []byte
		if e.decryptor.MatchDataSignature(data) {
			// match AcraStruct/AcraBlock
			logrus.WithField("decryptor", e.decryptor).Debugln("Try to decrypt for hashing")
			encryptedData = data
			processorContext := base.NewDataProcessorContext(e.keystore)
			accessContext := base.NewAccessContext(base.WithClientID(clientID))
			processorContext.Context = base.SetAccessContextToContext(processorContext.Context, accessContext)
			data, err = e.decryptor.Process(data, processorContext)
			if err != nil {
				logrus.WithError(err).WithField("decryptor", e.decryptor).Debugln("Not decrypted")
				return nil, err
			}
			hash = GenerateHMAC(key, data)
		} else {
			hash = GenerateHMAC(key, data)
			encryptedData, err = e.dataEncryptor.EncryptWithClientID(clientID, data, setting)
			if err != nil {
				return nil, err
			}
		}
		logrus.WithField("decryptor", e.decryptor).Debugln("Hash data")
		return append(hash, encryptedData...), nil
	}
	return data, nil
}
