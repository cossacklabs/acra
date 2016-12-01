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
	"fmt"
	. "github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"log"
	"os"
)

func GetPublicKeyFilename(id []byte) string {
	return fmt.Sprintf("%s_zone.pub", string(id))
}

type FilesystemKeyStore struct {
	keys      map[string][]byte
	directory string
}

func NewFilesystemKeyStore(directory string) *FilesystemKeyStore {
	return &FilesystemKeyStore{directory: directory, keys: make(map[string][]byte)}
}

func (*FilesystemKeyStore) get_zone_key_filename(id []byte) string {
	return fmt.Sprintf("%s_zone", string(id))
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

	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	keydir, err := GetDefaultKeyDir()
	if err != nil {
		return []byte{}, []byte{}, err
	}
	err = os.MkdirAll(keydir, 0700)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	err = ioutil.WriteFile(store.get_file_path(store.get_zone_key_filename(id)), keypair.Private.Value, 0600)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	// cache key
	store.keys[store.get_zone_key_filename(id)] = keypair.Private.Value
	return id, keypair.Public.Value, nil
}

func (store *FilesystemKeyStore) get_file_path(filename string) string {
	return fmt.Sprintf("%s%s%s", store.directory, string(os.PathSeparator), filename)
}

func (store *FilesystemKeyStore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := store.get_zone_key_filename(id)
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
	_, ok := store.keys[fname]
	if ok {
		return true
	}
	exists, _ := FileExists(store.get_file_path(fname))
	return exists
}

func (store *FilesystemKeyStore) GetProxyPublicKey(id []byte) (*keys.PublicKey, error) {
	fname := GetPublicKeyFilename(id)
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
	fname := fmt.Sprintf("%s_server", id)
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
