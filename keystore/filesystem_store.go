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
	. "github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sync"
)

var lock = sync.RWMutex{}

type FilesystemKeyStore struct {
	keys      map[string][]byte
	directory string
}

const (
	POISON_KEY_FILENAME = "poison_key"
)

func NewFilesystemKeyStore(directory string) (*FilesystemKeyStore, error) {
	fi, err := os.Stat(directory)
	if nil == err && runtime.GOOS == "linux" && fi.Mode().Perm().String() != "-rwx------" {
		log.Printf("Error: key store folder has an incorrect permissions")
		return nil, errors.New("key store folder has an incorrect permissions")
	}
	return &FilesystemKeyStore{directory: directory, keys: make(map[string][]byte)}, nil
}

func (*FilesystemKeyStore) get_zone_key_filename(id []byte) string {
	return fmt.Sprintf("%s_zone", string(id))
}

func (store *FilesystemKeyStore) get_zone_public_key_filename(id []byte) string {
	return fmt.Sprintf("%s.pub", store.get_zone_key_filename(id))
}

func (*FilesystemKeyStore) get_server_key_filename(id []byte) string {
	return fmt.Sprintf("%s_server", string(id))
}

func (*FilesystemKeyStore) get_server_decryption_key_filename(id []byte) string {
	return fmt.Sprintf("%s_decrypt", string(id))
}

func (*FilesystemKeyStore) get_proxy_key_filename(id []byte) string {
	return string(id)
}

func (store *FilesystemKeyStore) generate_key_pair(filename string) (*keys.Keypair, error) {
	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(store.directory, 0700)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(store.get_file_path(filename), keypair.Private.Value, 0600)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(store.get_file_path(fmt.Sprintf("%s.pub", filename)), keypair.Public.Value, 0644)
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

	keypair, err := store.generate_key_pair(store.get_zone_key_filename(id))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	lock.Lock()
	defer lock.Unlock()
	// cache key
	store.keys[store.get_zone_key_filename(id)] = keypair.Private.Value
	return id, keypair.Public.Value, nil
}

func (store *FilesystemKeyStore) get_file_path(filename string) string {
	return fmt.Sprintf("%s%s%s", store.directory, string(os.PathSeparator), filename)
}

func (store *FilesystemKeyStore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := store.get_zone_key_filename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	private_key, err := LoadPrivateKey(store.get_file_path(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = private_key.Value
	return private_key, nil
}

func (store *FilesystemKeyStore) HasZonePrivateKey(id []byte) bool {
	// add caching false answers. now if key doesn't exists than always checks on fs
	// it's system call and slow.
	if len(id) == 0 {
		return false
	}
	fname := store.get_zone_key_filename(id)
	lock.RLock()
	defer lock.RUnlock()
	_, ok := store.keys[fname]
	if ok {
		return true
	}
	exists, _ := FileExists(store.get_file_path(fname))
	return exists
}

func (store *FilesystemKeyStore) GetProxyPublicKey(id []byte) (*keys.PublicKey, error) {
	fname := store.get_zone_public_key_filename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PublicKey{Value: key}, nil
	}
	public_key, err := LoadPublicKey(store.get_file_path(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = public_key.Value
	return public_key, nil
}

func (store *FilesystemKeyStore) GetServerPrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := store.get_server_key_filename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	private_key, err := LoadPrivateKey(store.get_file_path(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = private_key.Value
	return private_key, nil
}

func (store *FilesystemKeyStore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := store.get_server_decryption_key_filename(id)
	lock.Lock()
	defer lock.Unlock()
	key, ok := store.keys[fname]
	if ok {
		log.Printf("Debug: load cached key: %s\n", fname)
		return &keys.PrivateKey{Value: key}, nil
	}
	private_key, err := LoadPrivateKey(store.get_file_path(fname))
	if err != nil {
		return nil, err
	}
	log.Printf("Debug: load key from fs: %s\n", fname)
	store.keys[fname] = private_key.Value
	return private_key, nil
}

func (store *FilesystemKeyStore) GenerateProxyKeys(id []byte) error {
	filename := store.get_proxy_key_filename(id)
	_, err := store.generate_key_pair(filename)
	if err != nil {
		return err
	}
	return nil
}
func (store *FilesystemKeyStore) GenerateServerKeys(id []byte) error {
	filename := store.get_server_key_filename(id)
	_, err := store.generate_key_pair(filename)
	if err != nil {
		return err
	}
	return nil
}

// generate key pair for data encryption/decryption
func (store *FilesystemKeyStore) GenerateDataEncryptionKeys(id []byte) error {
	_, err := store.generate_key_pair(store.get_server_decryption_key_filename(id))
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
	private_path := store.get_file_path(POISON_KEY_FILENAME)
	public_path := store.get_file_path(fmt.Sprintf("%s.pub", POISON_KEY_FILENAME))
	private_exists, err := FileExists(private_path)
	if err != nil {
		return nil, err
	}
	public_exists, err := FileExists(public_path)
	if err != nil {
		return nil, err
	}
	if private_exists && public_exists {
		private, err := LoadPrivateKey(private_path)
		if err != nil {
			return nil, err
		}
		public, err := LoadPublicKey(public_path)
		if err != nil {
			return nil, err
		}
		return &keys.Keypair{Public: public, Private: private}, nil
	} else {
		log.Println("Generate poison key pair")
		return store.generate_key_pair(POISON_KEY_FILENAME)
	}
}
