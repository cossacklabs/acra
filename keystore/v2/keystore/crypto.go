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

package keystore

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"

	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	log "github.com/sirupsen/logrus"
)

// Errors produced by master key validation:
var (
	ErrEqualMasterKeys = errors.New("encryption and signature master keys are equal")
)

// SerializedKeys is the serialized form of master keys.
type SerializedKeys struct {
	Encryption []byte `json:"encryption"`
	Signature  []byte `json:"signature"`
}

// NewMasterKeys generates a new set of master keys.
func NewMasterKeys() (*SerializedKeys, error) {
	encryptionKey, err := keystoreV1.GenerateSymmetricKey()
	if err != nil {
		return nil, err
	}
	signatureKey, err := keystoreV1.GenerateSymmetricKey()
	if err != nil {
		return nil, err
	}
	return &SerializedKeys{Encryption: encryptionKey, Signature: signatureKey}, nil
}

// NewSerializedMasterKeys generates a new set of master keys, already serialized into bytes.
func NewSerializedMasterKeys() ([]byte, error) {
	keys, err := NewMasterKeys()
	if err != nil {
		return nil, err
	}
	bytes, err := keys.Marshal()
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Marshal serializes master key into a byte buffer.
func (k *SerializedKeys) Marshal() ([]byte, error) {
	return json.Marshal(k)
}

// Unmarshal deserializes master keys from a byte buffer.
func (k *SerializedKeys) Unmarshal(buffer []byte) error {
	return json.Unmarshal(buffer, k)
}

// GetMasterKeysFromEnvironment reads master keys from default environment variable.
// Returns encryption key, signature key, error.
func GetMasterKeysFromEnvironment() ([]byte, []byte, error) {
	return GetMasterKeysFromEnvironmentVariable(keystoreV1.AcraMasterKeyVarName)
}

// GetMasterKeysFromEnvironmentVariable reads master keys from specified environment variable.
// Returns encryption key, signature key, error.
func GetMasterKeysFromEnvironmentVariable(varname string) ([]byte, []byte, error) {
	keys, err := getMasterKeysFromEnvironment(varname)
	if err != nil {
		return nil, nil, err
	}

	if subtle.ConstantTimeCompare(keys.Encryption, keys.Signature) == 1 {
		log.Warnf("%s: master keys must not be the same", varname)
		return nil, nil, ErrEqualMasterKeys
	}

	err = keystoreV1.ValidateMasterKey(keys.Encryption)
	if err != nil {
		log.WithError(err).Warnf("%s: invalid encryption key", varname)
		return nil, nil, err
	}
	err = keystoreV1.ValidateMasterKey(keys.Signature)
	if err != nil {
		log.WithError(err).Warnf("%s: invalid signature key", varname)
		return nil, nil, err
	}

	return keys.Encryption, keys.Signature, nil
}

func getMasterKeysFromEnvironment(varname string) (*SerializedKeys, error) {
	base64value := os.Getenv(varname)
	if len(base64value) == 0 {
		log.Warnf("%s environment variable is not set", varname)
		return nil, keystoreV1.ErrEmptyMasterKey
	}
	keyData, err := base64.StdEncoding.DecodeString(base64value)
	if err != nil {
		log.WithError(err).Warnf("Failed to decode %s", varname)
		return nil, err
	}
	keys := &SerializedKeys{}
	err = keys.Unmarshal(keyData)
	if err != nil {
		log.WithError(err).Warnf("Failed to parse %s", varname)
		return nil, err
	}
	return keys, nil
}

// NewSCellSuite creates default cryptography suite for KeyStore:
// - keys are encrypted by Themis Secure Cell in Seal mode
// - keystore is signed with HMAC-SHA-256
func NewSCellSuite(encryptionKey, signatureKey []byte) (*crypto.KeyStoreSuite, error) {
	return crypto.NewSCellSuite(encryptionKey, signatureKey)
}
