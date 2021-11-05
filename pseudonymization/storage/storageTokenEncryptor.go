/*
Copyright 2020, Cossack Labs Limited

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

package storage

import (
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/utils"
)

// TokenEncryptor interface used by storage implementations to encrypt data before saving
type TokenEncryptor interface {
	Encrypt(data []byte, ctx common.TokenContext) ([]byte, error)
	Decrypt(data []byte, ctx common.TokenContext) ([]byte, error)
}

type scellEncryptor struct {
	tokenKeystore keystore.SymmetricEncryptionKeyStore
}

// NewSCellEncryptor return new TokenEncryptor implementation with SecureCell usage
func NewSCellEncryptor(tokenKeystore keystore.SymmetricEncryptionKeyStore) (TokenEncryptor, error) {
	return &scellEncryptor{tokenKeystore: tokenKeystore}, nil
}

// Encrypt data with context
func (s *scellEncryptor) Encrypt(data []byte, ctx common.TokenContext) ([]byte, error) {
	var context []byte
	var keys [][]byte
	var err error
	if len(ctx.ZoneID) != 0 {
		context = ctx.ZoneID
		keys, err = s.tokenKeystore.GetZoneIDSymmetricKeys(ctx.ZoneID)
	} else {
		context = ctx.ClientID
		keys, err = s.tokenKeystore.GetClientIDSymmetricKeys(ctx.ClientID)
	}
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, keystore.ErrKeysNotFound
	}
	encrypted, err := acrablock.CreateAcraBlock(data, keys[0], context)
	for _, key := range keys {
		utils.ZeroizeSymmetricKey(key)
	}
	return encrypted, err
}

// Decrypt data according to context
func (s *scellEncryptor) Decrypt(data []byte, ctx common.TokenContext) ([]byte, error) {
	block, err := acrablock.NewAcraBlockFromData(data)
	if err != nil {
		return nil, err
	}
	var context []byte
	var keys [][]byte
	if len(ctx.ZoneID) != 0 {
		context = ctx.ZoneID
		keys, err = s.tokenKeystore.GetZoneIDSymmetricKeys(ctx.ZoneID)
	} else {
		context = ctx.ClientID
		keys, err = s.tokenKeystore.GetClientIDSymmetricKeys(ctx.ClientID)
	}
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, keystore.ErrKeysNotFound
	}
	decrypted, err := block.Decrypt(keys, context)
	for _, key := range keys {
		utils.ZeroizeSymmetricKey(key)
	}
	return decrypted, err
}
