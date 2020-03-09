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

// Package crypto provides implementations of cryptographic algorithms used by KeyStore.
package crypto

import (
	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/signature"
)

// KeyEncryptor defines how KeyStore encrypts keys.
type KeyEncryptor keystoreV1.KeyEncryptor

// KeyStoreSuite defines cryptography used by KeyStore.
type KeyStoreSuite struct {
	KeyEncryptor        KeyEncryptor
	SignatureAlgorithms []signature.Algorithm
}

// NewSCellSuite creates default cryptography suite for KeyStore:
// - keys are encrypted by Themis Secure Cell in Seal mode
// - key store is signed with HMAC-SHA-256
func NewSCellSuite(encryptionKey, signatureKey []byte) (*KeyStoreSuite, error) {
	encryptor, err := keystoreV1.NewSCellKeyEncryptor(encryptionKey)
	if err != nil {
		return nil, err
	}
	sha256, err := NewSignSha256(signatureKey)
	if err != nil {
		return nil, err
	}
	return &KeyStoreSuite{encryptor, []signature.Algorithm{sha256}}, nil
}
