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

package encryptor

import (
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/keystore"
)

// DataEncryptor replace raw data in queries with encrypted
type DataEncryptor interface {
	// EncryptWithZoneID encrypt with explicit zone id
	EncryptWithZoneID(zoneIDdata, data []byte) ([]byte, error)
	// EncryptWithClientID encrypt with explicit client id
	EncryptWithClientID(clientID, data []byte) ([]byte, error)
}

// AcrawriterDataEncryptor implement DataEncryptor and encrypt data with AcraStructs
type AcrawriterDataEncryptor struct {
	keystore keystore.PublicKeyStore
}

// NewAcrawriterDataEncryptor return new AcrawriterDataEncryptor initialized with keystore
func NewAcrawriterDataEncryptor(keystore keystore.PublicKeyStore) (*AcrawriterDataEncryptor, error) {
	return &AcrawriterDataEncryptor{keystore}, nil
}

// EncryptWithZoneID encrypt with explicit zone id
func (encryptor *AcrawriterDataEncryptor) EncryptWithZoneID(zoneID, data []byte) ([]byte, error) {
	publicKey, err := encryptor.keystore.GetZonePublicKey(zoneID)
	if err != nil {
		return nil, err
	}
	return acrawriter.CreateAcrastruct(data, publicKey, zoneID)
}

// EncryptWithClientID encrypt with explicit client id
func (encryptor *AcrawriterDataEncryptor) EncryptWithClientID(clientID, data []byte) ([]byte, error) {
	publicKey, err := encryptor.keystore.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		return nil, err
	}
	return acrawriter.CreateAcrastruct(data, publicKey, nil)
}
