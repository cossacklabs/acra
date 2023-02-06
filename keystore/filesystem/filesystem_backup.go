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
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// KeyBackuper export keys from KeyStore into encrypted bytes buffer
type KeyBackuper struct {
	keyStore         keystore.ServerKeyStore
	storage          Storage
	privateFolder    string
	publicFolder     string
	currentDecryptor keystore.KeyEncryptor
}

// NewKeyBackuper create, initialize and return new instance of KeyBackuper
func NewKeyBackuper(privateFolder, publicFolder string, storage Storage, decryptor keystore.KeyEncryptor, keyStore keystore.ServerKeyStore) (*KeyBackuper, error) {
	if publicFolder == "" {
		publicFolder = privateFolder
	}
	return &KeyBackuper{privateFolder: privateFolder, publicFolder: publicFolder, storage: storage, currentDecryptor: decryptor, keyStore: keyStore}, nil
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

	if isPublic(fname) {
		return false
	}

	return true
}

func isPublic(fname string) bool {
	if strings.HasSuffix(fname, ".pub") {
		return true
	}
	if strings.HasSuffix(fname, ".pub.old") {
		return true
	}
	return false
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
		relativeName := strings.Replace(f, filepath.Clean(basePath)+"/", "", -1)
		if isPrivate(relativeName) {
			keyContext := getContextFromFilename(relativeName)
			ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)

			content, err = encryptor.Decrypt(ctx, content, keyContext)
			if err != nil {
				return nil, err
			}
		}

		// additional verification of public key, there is no need to verify private keys
		// as private keys are encrypted and validated during description step
		if isPublic(relativeName) {
			if err := verifyPublicKey(&keys.PublicKey{
				Value: content,
			}); err != nil {
				return nil, err
			}
		}

		key := &keystore.Key{Name: relativeName, Content: content}
		output = append(output, key)
	}
	return output, nil
}

// Export keys from KeyStore encrypted with new key for backup
func (store *KeyBackuper) Export(exportIDs []keystore.ExportID, mode keystore.ExportMode) (*keystore.KeysBackup, error) {
	var exportedKeys []*keystore.Key
	var err error

	if len(exportIDs) != 0 {
		for _, exportID := range exportIDs {
			switch exportID.KeyKind {
			case keystore.KeyPoisonPublic:
				keypair, err := store.keyStore.GetPoisonKeyPair()
				if err != nil {
					log.WithError(err).Error("Cannot read poison record key pair")
					return nil, err
				}

				// additional verification of public key, there is no need to verify private keys
				// as private keys are encrypted and validated during description step
				if err := verifyPublicKey(keypair.Public); err != nil {
					log.WithError(err).Error("Invalid public key for export")
					return nil, err
				}

				exportedKeys = append(exportedKeys, &keystore.Key{
					Name:    poisonKeyFilenamePublic,
					Content: keypair.Public.Value,
				})
			case keystore.KeyPoisonPrivate:
				keypair, err := store.keyStore.GetPoisonKeyPair()
				if err != nil {
					log.WithError(err).Error("Cannot read poison record key pair")
					return nil, err
				}

				utils.ZeroizeBytes(keypair.Private.Value)
				exportedKeys = append(exportedKeys, &keystore.Key{
					Name:    PoisonKeyFilename,
					Content: keypair.Private.Value,
				})
			case keystore.KeyStoragePublic:
				key, err := store.keyStore.GetClientIDEncryptionPublicKey(exportID.ContextID)
				if err != nil {
					log.WithError(err).Error("Cannot read client storage public key")
					return nil, err
				}

				// additional verification of public key, there is no need to verify private keys
				// as private keys are encrypted and validated during description step
				if err := verifyPublicKey(key); err != nil {
					log.WithError(err).Error("Invalid public key for export")
					return nil, err
				}

				exportedKeys = append(exportedKeys, &keystore.Key{
					Name:    getPublicKeyFilename([]byte(GetServerDecryptionKeyFilename(exportID.ContextID))),
					Content: key.Value,
				})
			case keystore.KeyStoragePrivate:
				key, err := store.keyStore.GetServerDecryptionPrivateKey(exportID.ContextID)
				if err != nil {
					log.WithError(err).Error("Cannot read client storage private key")
					return nil, err
				}
				utils.ZeroizeBytes(key.Value)
				exportedKeys = append(exportedKeys, &keystore.Key{
					Name:    GetServerDecryptionKeyFilename(exportID.ContextID),
					Content: key.Value,
				})
			case keystore.KeySymmetric:
				key, err := store.keyStore.GetClientIDSymmetricKey(exportID.ContextID)
				if err != nil {
					log.WithError(err).Error("Cannot read client symmetric key")
					return nil, err
				}
				utils.ZeroizeBytes(key)
				exportedKeys = append(exportedKeys, &keystore.Key{
					Name:    getClientIDSymmetricKeyName(exportID.ContextID),
					Content: key,
				})
			case keystore.KeySearch:
				key, err := store.keyStore.GetHMACSecretKey(exportID.ContextID)
				if err != nil {
					log.WithError(err).Error("Cannot read client symmetric key")
					return nil, err
				}
				utils.ZeroizeBytes(key)
				exportedKeys = append(exportedKeys, &keystore.Key{
					Name:    getHmacKeyFilename(exportID.ContextID),
					Content: key,
				})
			default:
				return nil, errors.New("unexpected ExportID KeyKind")
			}
		}
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

		description, err := DescribeKeyFile(filepath.Base(key.Name))
		if err != nil {
			return nil, err
		}
		descriptions = append(descriptions, *description)
	}
	return descriptions, nil
}

func verifyPublicKey(pubKey *keys.PublicKey) error {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		return err
	}

	secureMessage := message.New(keypair.Private, pubKey)

	// try to encrypt some data with valid private file and passed public key
	// error is not nil mean that provided public key is invalid
	_, err = secureMessage.Wrap([]byte(`data`))
	if err != nil {
		return err
	}

	return nil
}
