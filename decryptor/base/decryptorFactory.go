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

package base

import (
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
)

// DecryptorSetting used to provide access methods for settings used by decryptor factories
type DecryptorSetting struct {
	withZone             bool
	checkPoisonRecord    bool
	wholeMatch           bool
	keystore             keystore.KeyStore
	poisonCallbacks      *PoisonCallbackStorage
	encryptorTableSchema config.TableSchemaStore
}

// EncryptorTableSchema return TableSchemaStore
func (setting *DecryptorSetting) EncryptorTableSchema() config.TableSchemaStore {
	return setting.encryptorTableSchema
}

// PoisonCallbacks return callbacks for dected poison record
func (setting *DecryptorSetting) PoisonCallbacks() *PoisonCallbackStorage {
	return setting.poisonCallbacks
}

// Keystore return keystore
func (setting *DecryptorSetting) Keystore() keystore.KeyStore {
	return setting.keystore
}

// WholeMatch return true if wholematch mode on
func (setting *DecryptorSetting) WholeMatch() bool {
	return setting.wholeMatch
}

// CheckPoisonRecord return true if should check poison records
func (setting *DecryptorSetting) CheckPoisonRecord() bool {
	return setting.checkPoisonRecord
}

// WithZone return true if zonemode on
func (setting *DecryptorSetting) WithZone() bool {
	return setting.withZone
}

// NewDecryptorSetting return new initialized DecryptorSetting
func NewDecryptorSetting(withZone, wholeMatch, checkPoisonRecord bool, poisonCallbacks *PoisonCallbackStorage, keystore keystore.KeyStore) *DecryptorSetting {
	return &DecryptorSetting{
		withZone:          withZone,
		checkPoisonRecord: checkPoisonRecord,
		wholeMatch:        wholeMatch,
		keystore:          keystore,
		poisonCallbacks:   poisonCallbacks,
	}
}

// DecryptorFactory interface to create db specific decryptors
type DecryptorFactory interface {
	New(clientID []byte) (Decryptor, error)
}
