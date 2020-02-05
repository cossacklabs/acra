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
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	keystoreV1 "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/signature"
	"github.com/cossacklabs/themis/gothemis/cell"
)

// KeyStoreSuite implements cryptography used by KeyStore.
type KeyStoreSuite interface {
	keystoreV1.KeyEncryptor
	signature.KeyedHMAC
}

// SCellSuite uses Themis Secure Cell in Seal mode to encrypt and decrypt keys.
type SCellSuite struct {
	scell   *cell.SecureCell
	signKey []byte
}

// NewSCellSuite creates new SCellSuite object with masterKey using Themis Secure Cell in Seal mode.
func NewSCellSuite(encryptionKey, signatureKey []byte) (*SCellSuite, error) {
	return &SCellSuite{
		scell:   cell.New(encryptionKey, cell.ModeSeal),
		signKey: signatureKey,
	}, nil
}

// Encrypt provided key in given context.
func (encryptor *SCellSuite) Encrypt(key, context []byte) ([]byte, error) {
	encrypted, _, err := encryptor.scell.Protect(key, context)
	return encrypted, err
}

// Decrypt provided key in given context.
func (encryptor *SCellSuite) Decrypt(key, context []byte) ([]byte, error) {
	return encryptor.scell.Unprotect(key, nil, context)
}

// HmacSha256 returns a HMAC-SHA-256 instance keyed by signature key.
func (encryptor *SCellSuite) HmacSha256() hash.Hash {
	return hmac.New(sha256.New, encryptor.signKey)
}
