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

package filesystem

import (
	"bytes"
	"encoding/gob"
	"path/filepath"
	"strings"
	"time"

	keystore2 "github.com/cossacklabs/acra/keystore"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
)

// KeyBackuper export keys from KeyStore into encrypted bytes buffer
type KeyBackuper struct {
	storage          Storage
	privateFolder    string
	publicFolder     string
	currentDecryptor keystore2.KeyEncryptor
}

// NewKeyBackuper create, initialize and return new instance of KeyBackuper
func NewKeyBackuper(privateFolder, publicFolder string, storage Storage, decryptor keystore2.KeyEncryptor) (*KeyBackuper, error) {
	if publicFolder == "" {
		publicFolder = privateFolder
	}
	return &KeyBackuper{privateFolder: privateFolder, publicFolder: publicFolder, storage: storage, currentDecryptor: decryptor}, nil
}

// ReadDir reads a directory and returns paths of items
func ReadDir(storage Storage, path string) ([]string, error) {
	output := make([]string, 0, 100)
	infos, err := storage.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, info := range infos {
		if info.IsDir() {
			paths, err := ReadDir(storage, filepath.Join(path, info.Name()))
			if err != nil {
				return nil, err
			}
			output = append(output, paths...)
			continue
		}
		output = append(output, filepath.Join(path, info.Name()))
	}
	return output, nil
}

func isPrivate(fname string) bool {
	if isHistoricalFilename(fname) {
		fname = filepath.Base(filepath.Dir(fname))
	}
	if fname == PoisonKeyFilename {
		return true
	}
	if strings.HasSuffix(fname, BasicAuthKeyFilename+".old") {
		return false
	}
	if strings.HasSuffix(fname, ".pub") {
		return false
	}
	if strings.HasSuffix(fname, ".pub.old") {
		return false
	}
	if fname == BasicAuthKeyFilename {
		return false
	}
	return true
}

func getIDFromFilename(fname string) []byte {
	if isHistoricalFilename(fname) {
		fname = filepath.Dir(fname)
	}
	if fname == PoisonKeyFilename {
		return []byte(fname)
	}
	if fname == getSymmetricKeyName(PoisonKeyFilename) {
		return []byte(fname[:len(fname)-len("_sym")])
	}
	fname = filepath.Base(fname)
	if strings.HasSuffix(fname, ".old") {
		fname = fname[:len(fname)-len(".old")]
	}
	if strings.HasSuffix(fname, "_hmac") {
		return []byte(fname[:len(fname)-len("_hmac")])
	}
	if strings.HasSuffix(fname, "_server") {
		return []byte(fname[:len(fname)-len("_server")])
	}
	if strings.HasSuffix(fname, "_translator") {
		return []byte(fname[:len(fname)-len("_translator")])
	}
	if strings.HasSuffix(fname, "_storage") {
		return []byte(fname[:len(fname)-len("_storage")])
	}
	if strings.HasSuffix(fname, "_storage_sym") {
		return []byte(fname[:len(fname)-len("_storage_sym")])
	}
	if strings.HasSuffix(fname, "_zone") {
		return []byte(fname[:len(fname)-len("_zone")])
	}
	if strings.HasSuffix(fname, "_zone_sym") {
		return []byte(fname[:len(fname)-len("_zone_sym")])
	}
	if strings.HasSuffix(fname, "_sym") {
		return []byte(fname[:len(fname)-len("_sym")])
	}

	if fname == BasicAuthKeyFilename {
		return []byte(BasicAuthKeyFilename)
	}
	return []byte(fname)
}

type dummyEncryptor struct{}

// Encrypt return data as is, used for tests
func (d dummyEncryptor) Encrypt(key, context []byte) ([]byte, error) {
	return key, nil
}

// Decrypt return data as is, used for tests
func (d dummyEncryptor) Decrypt(key, context []byte) ([]byte, error) {
	return key, nil
}

func isHistoricalFilename(name string) bool {
	_, err := time.Parse(HistoricalFileNameTimeFormat, filepath.Base(name))
	return err == nil
}

func readFilesAsKeys(files []string, basePath string, encryptor keystore2.KeyEncryptor, storage Storage) ([]*keystore.Key, error) {
	output := make([]*keystore.Key, 0, len(files))
	for _, f := range files {
		content, err := storage.ReadFile(f)
		if err != nil {
			return nil, err
		}
		// remove absolute first part, leave only relative to path
		relativeName := strings.Replace(f, basePath+"/", "", -1)
		if isPrivate(relativeName) {
			content, err = encryptor.Decrypt(content, getIDFromFilename(relativeName))
			if err != nil {
				return nil, err
			}
		}
		key := &keystore.Key{Name: relativeName, Content: content}
		output = append(output, key)
	}
	return output, nil
}

// Export keys from KeyStore encrypted with new key for backup
func (store *KeyBackuper) Export() (*keystore.KeysBackup, error) {
	var publicKeys []*keystore.Key
	var err error
	if store.publicFolder != store.privateFolder {
		publicFiles, err := ReadDir(store.storage, store.publicFolder)
		if err != nil {
			return nil, err
		}
		publicKeys, err = readFilesAsKeys(publicFiles, store.publicFolder, dummyEncryptor{}, store.storage)
		if err != nil {
			return nil, err
		}
	}

	privateFiles, err := ReadDir(store.storage, store.privateFolder)
	if err != nil {
		return nil, err
	}
	privateKeys, err := readFilesAsKeys(privateFiles, store.privateFolder, store.currentDecryptor, store.storage)
	if err != nil {
		return nil, err
	}
	defer func(keys []*keystore.Key) {
		for _, key := range keys {
			utils.ZeroizeBytes(key.Content)
		}
	}(privateKeys)

	keys := make([]*keystore.Key, 0, len(publicKeys)+len(privateKeys))
	keys = append(keys, privateKeys...)
	keys = append(keys, publicKeys...)
	buf := &bytes.Buffer{}
	encoder := gob.NewEncoder(buf)
	if err := encoder.Encode(keys); err != nil {
		return nil, err
	}
	defer func(buf *bytes.Buffer) {
		utils.ZeroizeBytes(buf.Bytes())
	}(buf)
	newMasterKey, err := keystore2.GenerateSymmetricKey()
	if err != nil {
		return nil, err
	}
	encryptor, err := keystore2.NewSCellKeyEncryptor(newMasterKey)
	if err != nil {
		return nil, err
	}
	encryptedKeys, err := encryptor.Encrypt(buf.Bytes(), nil)
	if err != nil {
		return nil, err
	}
	return &keystore.KeysBackup{Keys: encryptedKeys, MasterKey: newMasterKey}, nil
}

// Import keys from backup to current keystore
func (store *KeyBackuper) Import(backup *keystore.KeysBackup) error {
	decryptor, err := keystore2.NewSCellKeyEncryptor(backup.MasterKey)
	if err != nil {
		return err
	}
	decryptedData, err := decryptor.Decrypt(backup.Keys, nil)
	if err != nil {
		return err
	}
	defer utils.ZeroizeBytes(decryptedData)

	decoder := gob.NewDecoder(bytes.NewReader(decryptedData))
	keys := []*keystore.Key{}
	if err := decoder.Decode(&keys); err != nil {
		return err
	}
	for _, key := range keys {
		isPrivateKey := isPrivate(key.Name)
		filePermission := publicFileMode
		fullName := filepath.Join(store.privateFolder, key.Name)
		content := key.Content
		if isPrivateKey {
			content, err = store.currentDecryptor.Encrypt(key.Content, getIDFromFilename(key.Name))
			// anyway fill with zeros
			utils.ZeroizeBytes(key.Content)
			if err != nil {
				return err
			}
			filePermission = PrivateFileMode
		} else {
			if store.publicFolder != "" {
				fullName = filepath.Join(store.publicFolder, key.Name)
			}
		}
		dirName := filepath.Dir(fullName)
		if err := store.storage.MkdirAll(dirName, keyDirMode); err != nil {
			return err
		}

		if err := store.storage.WriteFile(fullName, content, filePermission); err != nil {
			return err
		}
	}
	return nil
}
