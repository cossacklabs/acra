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

package filesystem

import (
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"path/filepath"
)

// TranslatorFileSystemKeyStore stores AcraTranslator keys configuration
type TranslatorFileSystemKeyStore struct {
	*KeyStore
	directory string
	encryptor keystore.KeyEncryptor
}

// NewTranslatorFileSystemKeyStoreFromServerStore create TranslatorKeyStore which inherit KeyStore
func NewTranslatorFileSystemKeyStoreFromServerStore(directory string, encryptor keystore.KeyEncryptor, store *KeyStore)(*TranslatorFileSystemKeyStore, error){
	return &TranslatorFileSystemKeyStore{KeyStore: store, directory: directory, encryptor: encryptor}, nil
}

// NewTranslatorFileSystemKeyStore creates new TranslatorFileSystemKeyStore
func NewTranslatorFileSystemKeyStore(directory string, encryptor keystore.KeyEncryptor, cacheSize int) (*TranslatorFileSystemKeyStore, error) {
	fsKeystore, err := NewFileSystemKeyStoreWithCacheSize(directory, encryptor, cacheSize)
	if err != nil {
		return nil, err
	}
	return &TranslatorFileSystemKeyStore{KeyStore: fsKeystore, directory: directory, encryptor: encryptor}, nil
}

// CheckIfPrivateKeyExists checks if Keystore has Translator transport private key for establishing Secure Session connection,
// returns true if key exists in fs.
func (store *TranslatorFileSystemKeyStore) CheckIfPrivateKeyExists(id []byte) (bool, error) {
	_, err := ioutil.ReadFile(filepath.Join(store.directory, getTranslatorKeyFilename(id)))
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetPrivateKey reads and decrypts Translator transport private key for establishing Secure Session connection.
func (store *TranslatorFileSystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filepath.Join(store.directory, getTranslatorKeyFilename(id)))
	if err != nil {
		return nil, err
	}

	var privateKey []byte
	if privateKey, err = store.encryptor.Decrypt(keyData, id); err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: privateKey}, nil
}
