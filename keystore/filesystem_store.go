// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keystore

import (
	"errors"
	"fmt"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var lock = sync.RWMutex{}

type FilesystemKeyStore struct {
	keys      map[string][]byte
	directory string
}

const (
	POISON_KEY_FILENAME = ".poison_key/poison_key"
)

func NewFilesystemKeyStore(directory string) (*FilesystemKeyStore, error) {
	directory, err := utils.AbsPath(directory)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(directory)
	if nil == err && runtime.GOOS == "linux" && fi.Mode().Perm().String() != "-rwx------" {
		log.Println("Error: key store folder has an incorrect permissions")
		return nil, errors.New("key store folder has an incorrect permissions")
	}
	return &FilesystemKeyStore{directory: directory, keys: make(map[string][]byte)}, nil
}

func (*FilesystemKeyStore) getZoneKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_zone", string(id))
}

func (store *FilesystemKeyStore) getZonePublicKeyFilename(id []byte) string {
	return fmt.Sprintf("%s.pub", store.getZoneKeyFilename(id))
}

func (*FilesystemKeyStore) getServerKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_server", string(id))
}

func (*FilesystemKeyStore) getServerDecryptionKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_storage", string(id))
}

func (*FilesystemKeyStore) getProxyKeyFilename(id []byte) string {
	return string(id)
}

func (store *FilesystemKeyStore) generateKeyPair(filename string) (*keys.Keypair, error) {
	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	dirpath := filepath.Dir(store.getFilePath(filename))
	err = os.MkdirAll(dirpath, 0700)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(store.getFilePath(filename), keypair.Private.Value, 0600)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(store.getFilePath(fmt.Sprintf("%s.pub", filename)), keypair.Public.Value, 0644)
	if err != nil {
		return nil, err
	}
	return keypair, nil
}

func (store *FilesystemKeyStore) GenerateZoneKey() ([]byte, []byte, error) {
	/* save private key in fs, return id and public key*/
	var id []byte
	for {
		// generate until key not exists
		id = zone.GenerateZoneId()
		if !store.HasZonePrivateKey(id) {
			break
		}
	}

	keypair, err := store.generateKeyPair(store.getZoneKeyFilename(id))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	lock.Lock()
	defer lock.Unlock()
	// cache key
	store.keys[store.getZoneKeyFilename(id)] = keypair.Private.Value
	return id, keypair.Public.Value, nil
}

func (store *FilesystemKeyStore) getFilePath(filename string) string {
	return fmt.Sprintf("%s%s%s", store.directory, string(os.PathSeparator), filename)
}

func (store *FilesystemKeyStore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := store.getZoneKeyFilename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	privateKey, err := utils.LoadPrivateKey(store.getFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = privateKey.Value
	return privateKey, nil
}

func (store *FilesystemKeyStore) HasZonePrivateKey(id []byte) bool {
	if !ValidateId(id) {
		return false
	}
	// add caching false answers. now if key doesn't exists than always checks on fs
	// it's system call and slow.
	if len(id) == 0 {
		return false
	}
	fname := store.getZoneKeyFilename(id)
	lock.RLock()
	defer lock.RUnlock()
	_, ok := store.keys[fname]
	if ok {
		return true
	}
	exists, _ := utils.FileExists(store.getFilePath(fname))
	return exists
}

func (store *FilesystemKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := store.getZonePublicKeyFilename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PublicKey{Value: key}, nil
	}
	publicKey, err := utils.LoadPublicKey(store.getFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = publicKey.Value
	return publicKey, nil
}

func (store *FilesystemKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := store.getServerKeyFilename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	privateKey, err := utils.LoadPrivateKey(store.getFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = privateKey.Value
	return privateKey, nil
}

func (store *FilesystemKeyStore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	if !ValidateId(id) {
		return nil, ErrInvalidClientId
	}
	fname := store.getServerDecryptionKeyFilename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	privateKey, err := utils.LoadPrivateKey(store.getFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = privateKey.Value
	return privateKey, nil
}

func (store *FilesystemKeyStore) GenerateProxyKeys(id []byte) error {
	if !ValidateId(id) {
		return ErrInvalidClientId
	}
	filename := store.getProxyKeyFilename(id)
	_, err := store.generateKeyPair(filename)
	if err != nil {
		return err
	}
	return nil
}
func (store *FilesystemKeyStore) GenerateServerKeys(id []byte) error {
	if !ValidateId(id) {
		return ErrInvalidClientId
	}
	filename := store.getServerKeyFilename(id)
	_, err := store.generateKeyPair(filename)
	if err != nil {
		return err
	}
	return nil
}

// generate key pair for data encryption/decryption
func (store *FilesystemKeyStore) GenerateDataEncryptionKeys(id []byte) error {
	if !ValidateId(id) {
		return ErrInvalidClientId
	}
	_, err := store.generateKeyPair(store.getServerDecryptionKeyFilename(id))
	if err != nil {
		return err
	}
	return nil
}

// clear all cached keys
func (store *FilesystemKeyStore) Reset() {
	store.keys = make(map[string][]byte)
}

func (store *FilesystemKeyStore) GetPoisonKeyPair() (*keys.Keypair, error) {
	privatePath := store.getFilePath(POISON_KEY_FILENAME)
	publicPath := store.getFilePath(fmt.Sprintf("%s.pub", POISON_KEY_FILENAME))
	privateExists, err := utils.FileExists(privatePath)
	if err != nil {
		return nil, err
	}
	publicExists, err := utils.FileExists(publicPath)
	if err != nil {
		return nil, err
	}
	if privateExists && publicExists {
		private, err := utils.LoadPrivateKey(privatePath)
		if err != nil {
			return nil, err
		}
		public, err := utils.LoadPublicKey(publicPath)
		if err != nil {
			return nil, err
		}
		return &keys.Keypair{Public: public, Private: private}, nil
	}
	log.Println("Info: Generate poison key pair")
	return store.generateKeyPair(POISON_KEY_FILENAME)
}
