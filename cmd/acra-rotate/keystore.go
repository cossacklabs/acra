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

package main

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/themis/gothemis/keys"
)

type rotateKeystore struct {
	*filesystem.KeyStore
}

// NewKeyStore create new KeyStore for rotation
func NewKeyStore(dir string, encryptor keystore.KeyEncryptor) (KeyStore, error) {
	store, err := filesystem.NewFilesystemKeyStore(dir, encryptor)
	if err != nil {
		return nil, err
	}
	return &rotateKeystore{store}, nil
}

// KeyStore interface used for acrastruct rotation
type KeyStore interface {
	SaveZoneKeypair([]byte, *keys.Keypair) error
	SaveClientIDKeypair([]byte, *keys.Keypair) error
	GetZonePrivateKey([]byte) (*keys.PrivateKey, error)
	GetServerDecryptionPrivateKey([]byte) (*keys.PrivateKey, error)
}

// SaveClientIDKeypair save keypair related with cliend id using filesystem keystore
func (store *rotateKeystore) SaveClientIDKeypair(clientID []byte, kp *keys.Keypair) error {
	filename := filesystem.GetServerDecryptionKeyFilename(clientID)
	return store.SaveKeyPairWithFilename(kp, filename, clientID)
}
