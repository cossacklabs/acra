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
	"encoding/base64"
	"os"

	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	log "github.com/sirupsen/logrus"
)

// Master key environment variable names:
const (
	AcraMasterEncryptionKeyVarName = "ACRA_MASTER_ENCRYPTION_KEY"
	AcraMasterSignatureKeyVarName  = "ACRA_MASTER_SIGNATURE_KEY"
)

// GetMasterKeysFromEnvironment reads master keys from default environment variables.
// Returns encryption key, signature key, error.
func GetMasterKeysFromEnvironment() ([]byte, []byte, error) {
	encryptionKey, err := getMasterKeyFromEnvironment(AcraMasterEncryptionKeyVarName)
	if err != nil {
		log.WithError(err).Errorf("cannot read %v", AcraMasterEncryptionKeyVarName)
		return nil, nil, err
	}
	signatureKey, err := getMasterKeyFromEnvironment(AcraMasterSignatureKeyVarName)
	if err != nil {
		log.WithError(err).Errorf("cannot read %v", AcraMasterSignatureKeyVarName)
		return nil, nil, err
	}
	return encryptionKey, signatureKey, nil
}

func getMasterKeyFromEnvironment(name string) (key []byte, err error) {
	base64value := os.Getenv(name)
	if len(base64value) == 0 {
		return nil, keystoreV1.ErrEmptyMasterKey
	}
	key, err = base64.StdEncoding.DecodeString(base64value)
	if err != nil {
		return
	}
	err = keystoreV1.ValidateMasterKey(key)
	if err != nil {
		return
	}
	return
}

// NewSCellSuite creates default cryptography suite for KeyStore:
// - keys are encrypted by Themis Secure Cell in Seal mode
// - key store is signed with HMAC-SHA-256
func NewSCellSuite(encryptionKey, signatureKey []byte) (*crypto.KeyStoreSuite, error) {
	return crypto.NewSCellSuite(encryptionKey, signatureKey)
}
