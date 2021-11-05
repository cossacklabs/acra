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
	"time"

	"github.com/cossacklabs/acra/pseudonymization/common"
)

type secureWrapper struct {
	encryptor TokenEncryptor
	storage   common.TokenStorage
}

// WrapStorageWithEncryption return storage as wrapper which encrypts data before saving and decrypt after fetching data
// from wrapped storage
func WrapStorageWithEncryption(storage common.TokenStorage, encryptor TokenEncryptor) common.TokenStorage {
	return &secureWrapper{encryptor, storage}
}

// Save encrypt and save data with defined id and context
func (s *secureWrapper) Save(id []byte, context common.TokenContext, data []byte) error {
	encrypted, err := s.encryptor.Encrypt(data, context)
	if err != nil {
		return err
	}
	return s.storage.Save(id, context, encrypted)
}

// Get data and decrypt with defined id and context
func (s *secureWrapper) Get(id []byte, context common.TokenContext) ([]byte, error) {
	val, err := s.storage.Get(id, context)
	if err != nil {
		return nil, err
	}
	return s.encryptor.Decrypt(val, context)
}

// Stat returns metadata of a token entry.
func (s *secureWrapper) Stat(id []byte, context common.TokenContext) (common.TokenMetadata, error) {
	return s.storage.Stat(id, context)
}

// SetAccessTimeGranularity sets access time granularity.
func (s *secureWrapper) SetAccessTimeGranularity(granularity time.Duration) error {
	return s.storage.SetAccessTimeGranularity(granularity)
}

// Iterate over token metadata in the storage.
func (s *secureWrapper) VisitMetadata(cb func(dataLength int, metadata common.TokenMetadata) (common.TokenAction, error)) error {
	return s.storage.VisitMetadata(cb)
}
