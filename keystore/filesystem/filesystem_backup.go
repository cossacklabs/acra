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
	"context"
	"encoding/gob"
	"path/filepath"
	"strings"
	"time"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// KeyBackuper export keys from KeyStore into encrypted bytes buffer
type KeyBackuper struct {
	storage          Storage
	privateFolder    string
	publicFolder     string
	currentDecryptor keystore.KeyEncryptor
}

// NewKeyBackuper create, initialize and return new instance of KeyBackuper
func NewKeyBackuper(privateFolder, publicFolder string, storage Storage, decryptor keystore.KeyEncryptor) (*KeyBackuper, error) {
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
	if strings.HasSuffix(fname, ".pub") {
		return false
	}
	if strings.HasSuffix(fname, ".pub.old") {
		return false
	}
	return true
}

func getContextFromFilename(fname string) keystore.KeyContext {
	if isHistoricalFilename(fname) {
		fname = filepath.Dir(fname)
	}
	if fname == PoisonKeyFilename {
		return keystore.NewKeyContext(keystore.PurposePoisonRecordKeyPair, []byte(fname))
	}
	if fname == getSymmetricKeyName(PoisonKeyFilename) {
		return keystore.NewKeyContext(keystore.PurposePoisonRecordSymmetricKey, []byte(fname[:len(fname)-len("_sym")]))
	}
	fname = filepath.Base(fname)
	if strings.HasSuffix(fname, ".old") {
		fname = fname[:len(fname)-len(".old")]
	}
	if strings.HasSuffix(fname, "_hmac") {
		return keystore.NewClientIDKeyContext(keystore.PurposeSearchHMAC, []byte(fname[:len(fname)-len("_hmac")]))
	}
	if strings.HasSuffix(fname, "_server") {
		return keystore.NewClientIDKeyContext(keystore.PurposeLegacy, []byte(fname[:len(fname)-len("_server")]))
	}
	if strings.HasSuffix(fname, "_translator") {
		return keystore.NewClientIDKeyContext(keystore.PurposeLegacy, []byte(fname[:len(fname)-len("_translator")]))
	}
	if strings.HasSuffix(fname, "_storage") {
		return keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, []byte(fname[:len(fname)-len("_storage")]))
	}
	if strings.HasSuffix(fname, "_storage_sym") {
		return keystore.NewClientIDKeyContext(keystore.PurposeStorageClientSymmetricKey, []byte(fname[:len(fname)-len("_storage_sym")]))
	}

	return keystore.NewKeyContext(keystore.PurposeUndefined, []byte(fname))
}

type dummyEncryptor struct{}

// Encrypt return data as is, used for tests
func (d dummyEncryptor) Encrypt(ctx context.Context, key []byte, keyContext keystore.KeyContext) ([]byte, error) {
	return key, nil
}

// Decrypt return data as is, used for tests
func (d dummyEncryptor) Decrypt(ctx context.Context, key []byte, keyContext keystore.KeyContext) ([]byte, error) {
	return key, nil
}

func isHistoricalFilename(name string) bool {
	_, err := time.Parse(HistoricalFileNameTimeFormat, filepath.Base(name))
	return err == nil
}

func readFilesAsKeys(files []string, basePath string, encryptor keystore.KeyEncryptor, storage Storage) ([]*keystore.Key, error) {
	output := make([]*keystore.Key, 0, len(files))
	for _, f := range files {
		content, err := storage.ReadFile(f)
		if err != nil {
			return nil, err
		}
		// remove absolute first part, leave only relative to path
		relativeName := strings.Replace(f, filepath.Join(basePath)+"/", "", -1)
		if isPrivate(relativeName) {
			keyContext := getContextFromFilename(relativeName)
			ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)

			content, err = encryptor.Decrypt(ctx, content, keyContext)
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
func (store *KeyBackuper) Export(exportPaths []string, mode keystore.ExportMode) (*keystore.KeysBackup, error) {
	var exportedKeys []*keystore.Key
	var err error

	if len(exportPaths) != 0 {
		keyPaths := make([]string, 0, len(exportPaths))
		for _, path := range exportPaths {
			keyPaths = append(keyPaths, filepath.Join(store.privateFolder, path))
		}

		keys, err := readFilesAsKeys(keyPaths, store.privateFolder, store.currentDecryptor, store.storage)
		if err != nil {
			return nil, err
		}
		exportedKeys = append(exportedKeys, keys...)

		defer func(keys []*keystore.Key) {
			for _, key := range keys {
				utils.ZeroizeBytes(key.Content)
			}
		}(keys)

	} else {
		if (mode == keystore.ExportAllKeys || mode == keystore.ExportPublicOnly) && store.publicFolder != store.privateFolder {
			publicFiles, err := ReadDir(store.storage, store.publicFolder)
			if err != nil {
				return nil, err
			}
			publicKeys, err := readFilesAsKeys(publicFiles, store.publicFolder, dummyEncryptor{}, store.storage)
			if err != nil {
				return nil, err
			}
			exportedKeys = append(exportedKeys, publicKeys...)
		}

		if mode == keystore.ExportPrivateKeys || mode == keystore.ExportAllKeys {
			privateFiles, err := ReadDir(store.storage, store.privateFolder)
			if err != nil {
				return nil, err
			}
			privateKeys, err := readFilesAsKeys(privateFiles, store.privateFolder, store.currentDecryptor, store.storage)
			if err != nil {
				return nil, err
			}
			exportedKeys = append(exportedKeys, privateKeys...)

			defer func(keys []*keystore.Key) {
				for _, key := range keys {
					utils.ZeroizeBytes(key.Content)
				}
			}(privateKeys)
		}
	}

	buf := &bytes.Buffer{}
	encoder := gob.NewEncoder(buf)
	if err := encoder.Encode(exportedKeys); err != nil {
		return nil, err
	}
	defer func(buf *bytes.Buffer) {
		utils.ZeroizeBytes(buf.Bytes())
	}(buf)
	newMasterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		return nil, err
	}
	encryptor, err := keystore.NewSCellKeyEncryptor(newMasterKey)
	if err != nil {
		return nil, err
	}

	encryptedKeys, err := encryptor.Encrypt(context.Background(), buf.Bytes(), keystore.NewEmptyKeyContext(nil))
	if err != nil {
		return nil, err
	}
	return &keystore.KeysBackup{Data: encryptedKeys, Keys: newMasterKey}, nil
}

// Import keys from backup to current keystore
func (store *KeyBackuper) Import(backup *keystore.KeysBackup) ([]keystore.KeyDescription, error) {
	decryptor, err := keystore.NewSCellKeyEncryptor(backup.Keys)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decryptor.Decrypt(context.Background(), backup.Data, keystore.NewEmptyKeyContext(nil))
	if err != nil {
		return nil, err
	}
	defer utils.ZeroizeBytes(decryptedData)

	decoder := gob.NewDecoder(bytes.NewReader(decryptedData))
	keys := []*keystore.Key{}
	if err := decoder.Decode(&keys); err != nil {
		return nil, err
	}

	descriptions := make([]keystore.KeyDescription, 0, len(keys))
	for _, key := range keys {
		isPrivateKey := isPrivate(key.Name)
		filePermission := publicFileMode
		fullName := filepath.Join(store.privateFolder, key.Name)
		content := key.Content
		if isPrivateKey {

			keyContext := getContextFromFilename(key.Name)
			content, err = store.currentDecryptor.Encrypt(context.Background(), key.Content, keyContext)
			// anyway fill with zeros
			utils.ZeroizeBytes(key.Content)
			if err != nil {
				return nil, err
			}
			filePermission = PrivateFileMode
		} else {
			if store.publicFolder != "" {
				fullName = filepath.Join(store.publicFolder, key.Name)
			}
		}
		dirName := filepath.Dir(fullName)
		if err := store.storage.MkdirAll(dirName, keyDirMode); err != nil {
			return nil, err
		}

		if err := store.storage.WriteFile(fullName, content, filePermission); err != nil {
			return nil, err
		}

		description, err := DescribeKeyFile(key.Name)
		if err != nil {
			return nil, err
		}
		descriptions = append(descriptions, *description)
	}
	return descriptions, nil
}
