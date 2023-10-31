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
	"context"

	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/keystore"
)

// DataEncryptorContext store data for DataEncryptor
type DataEncryptorContext struct {
	Keystore keystore.DataEncryptorKeyStore
	Context  context.Context
}

// DataEncryptor replace raw data in queries with encrypted
type DataEncryptor interface {
	// EncryptWithClientID encrypt with explicit client id
	EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error)
}

// ChainDataEncryptor implements DataEncryptor and pass data to all encryptors on each call
// All encryptors should return untouched data if don't do anything with data
type ChainDataEncryptor struct {
	encryptors []DataEncryptor
}

// NewChainDataEncryptor return new ChainDataEncryptor
func NewChainDataEncryptor(encryptors ...DataEncryptor) *ChainDataEncryptor {
	return &ChainDataEncryptor{
		encryptors: encryptors,
	}
}

// EncryptWithClientID encrypt with explicit client id
func (chainEncryptor *ChainDataEncryptor) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	outData := data
	var err error
	for _, encryptor := range chainEncryptor.encryptors {
		outData, err = encryptor.EncryptWithClientID(clientID, outData, setting)
		if err != nil {
			return data, err
		}
	}
	return outData, nil
}

// CheckFunction return true if operation should be skipped
type CheckFunction func(setting config.ColumnEncryptionSetting) bool

// EmptyCheckFunction always return false
func EmptyCheckFunction(setting config.ColumnEncryptionSetting) bool {
	return false
}

// StandaloneAcraBlockEncryptorFilterFunction return true if operation should be applied only if setting configured for
// encryption without any other operations like tokenization/masking
func StandaloneAcraBlockEncryptorFilterFunction(setting config.ColumnEncryptionSetting) bool {
	return setting.GetCryptoEnvelope() != config.CryptoEnvelopeTypeAcraBlock || !setting.OnlyEncryption()
}

func standaloneEncryptorFilterFunction(setting config.ColumnEncryptionSetting) bool {
	return setting.GetCryptoEnvelope() != config.CryptoEnvelopeTypeAcraStruct || !setting.OnlyEncryption()
}

// StandaloneAcraStructEncryptorFilterFunction return true if operation should be applied only if setting configured for
// encryption without any other operations like tokenization/masking
func StandaloneAcraStructEncryptorFilterFunction(setting config.ColumnEncryptionSetting) bool {
	return setting.GetCryptoEnvelope() != config.CryptoEnvelopeTypeAcraStruct || !setting.OnlyEncryption()
}

// AcrawriterDataEncryptor implement DataEncryptor and encrypt data with AcraStructs
type AcrawriterDataEncryptor struct {
	keystore  keystore.PublicKeyStore
	checkFunc CheckFunction
}

// NewAcrawriterDataEncryptor return new AcrawriterDataEncryptor initialized with keystore
func NewAcrawriterDataEncryptor(keystore keystore.PublicKeyStore) (*AcrawriterDataEncryptor, error) {
	return &AcrawriterDataEncryptor{keystore, EmptyCheckFunction}, nil
}

// NewStandaloneDataEncryptor return new DataEncryptor that uses AcraStruct to encrypt data as separate OnColumn processor
// and checks that passed setting configured only for transparent AcraStruct encryption
func NewStandaloneDataEncryptor(keystore keystore.PublicKeyStore) (*AcrawriterDataEncryptor, error) {
	return &AcrawriterDataEncryptor{keystore, standaloneEncryptorFilterFunction}, nil
}

// EncryptWithClientID encrypt with explicit client id
func (encryptor *AcrawriterDataEncryptor) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if encryptor.checkFunc(setting) {
		return data, nil
	}
	if err := acrastruct.ValidateAcraStructLength(data); err == nil {
		return data, nil
	}
	publicKey, err := encryptor.keystore.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		return nil, err
	}
	return acrastruct.CreateAcrastruct(data, publicKey, nil)
}
