/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package filesystem

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// KeyExportEnumerator provides a list of key paths to be exported.
type KeyExportEnumerator interface {
	EnumerateExportedKeyPaths() ([]string, error)
}

// KeyExport allows to export plaintext key material by generic key description rather than specific purpose.
type KeyExport interface {
	KeyExportEnumerator

	ExportPublicKey(key ExportedKey) (*keys.PublicKey, error)
	ExportPrivateKey(key ExportedKey) (*keys.PrivateKey, error)
	ExportKeyPair(key ExportedKey) (*keys.Keypair, error)
	ExportSymmetricKey(key ExportedKey) ([]byte, error)
	ExportPlaintextSymmetricKey(key ExportedKey) ([]byte, error)
}

// KeyFileClassifier defines how to export keys stored in files.
// It divines the purpose of the key by its path.
// Return nil if the path should not be exported (e.g., if it's not a key).
type KeyFileClassifier interface {
	ClassifyExportedKey(path string) *ExportedKey
}

// ExportedKey describes a key that can be exported from keystore.
//
// `Purpose` describes the purpose of this key.
// This is one of the `Purpose...` constants exported by this module.
//
// `ID` is either client ID, or zone ID, or nil depending on the purpose.
//
// `*Path` fields will be empty when not applicable.
// For example, symmetric keys will not have public or private parts,
// and only public or private key of a key pair may be present.
type ExportedKey struct {
	PublicPath    string
	PrivatePath   string
	SymmetricPath string
	KeyContext    keystore.KeyContext
}

// Exported key purpose constants:

// ExportPublicKey loads a public key for export.
func (store *KeyStore) ExportPublicKey(key ExportedKey) (*keys.PublicKey, error) {
	if key.PublicPath == "" {
		return nil, nil
	}
	// This is getPublicKeyByFilename() but without cache thrashing.
	return utils.LoadPublicKey(key.PublicPath)
}

// ExportPrivateKey loads a private key for export.
func (store *KeyStore) ExportPrivateKey(key ExportedKey) (*keys.PrivateKey, error) {
	if key.PrivatePath == "" {
		return nil, nil
	}
	// This is getPrivateKeyByFilename() but without cache thrashing.
	privateKey, err := utils.LoadPrivateKey(key.PrivatePath)
	if err != nil {
		return nil, err
	}

	decryptedKey, err := store.encryptor.Decrypt(context.Background(), privateKey.Value, key.KeyContext)
	if err != nil {
		return nil, err
	}
	privateKey.Value = decryptedKey
	return privateKey, nil
}

// ExportKeyPair loads a key pair for export.
func (store *KeyStore) ExportKeyPair(key ExportedKey) (*keys.Keypair, error) {
	publicKey, err := store.ExportPublicKey(key)
	if err != nil {
		return nil, err
	}
	privateKey, err := store.ExportPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &keys.Keypair{Public: publicKey, Private: privateKey}, nil
}

// ExportSymmetricKey loads a symmetric key for export.
func (store *KeyStore) ExportSymmetricKey(key ExportedKey) ([]byte, error) {
	if key.SymmetricPath == "" {
		return nil, nil
	}
	encrypted, err := utils.ReadFile(key.SymmetricPath)
	if err != nil {
		return nil, err
	}

	keyValue, err := store.encryptor.Decrypt(context.Background(), encrypted, key.KeyContext)
	if err != nil {
		return nil, err
	}
	return keyValue, nil
}

// ExportPlaintextSymmetricKey loads an unencrypted symmetric key for export.
func (store *KeyStore) ExportPlaintextSymmetricKey(key ExportedKey) ([]byte, error) {
	if key.SymmetricPath == "" {
		return nil, nil
	}
	return utils.ReadFile(key.SymmetricPath)
}

// DefaultKeyFileClassifier is a KeyFileClassifier for standard key types.
type DefaultKeyFileClassifier struct{}

var defaultClassifier = &DefaultKeyFileClassifier{}

// EnumerateExportedKeys prepares a list of keys that can be exported.
// The keys are classified with default key file classifier.
func EnumerateExportedKeys(enumerator KeyExportEnumerator) ([]ExportedKey, error) {
	return EnumerateExportedKeysByClass(enumerator, defaultClassifier)
}

// EnumerateExportedKeysByClass prepares a list of keys that can be exported.
// The keys are classified with the provided classifier.
func EnumerateExportedKeysByClass(enumerator KeyExportEnumerator, classifier KeyFileClassifier) ([]ExportedKey, error) {
	keyPaths, err := enumerator.EnumerateExportedKeyPaths()
	if err != nil {
		return nil, err
	}

	keyMap := make(map[string]*ExportedKey)
	for _, path := range keyPaths {
		if key := classifier.ClassifyExportedKey(path); key != nil {
			id := key.fusedID()
			keyInMap, exists := keyMap[id]
			if exists {
				keyInMap.addPathFrom(key)
			} else {
				keyMap[id] = key
			}
		}
	}

	exportedKeys := make([]ExportedKey, 0, len(keyMap))
	for _, key := range keyMap {
		exportedKeys = append(exportedKeys, *key)
	}
	return exportedKeys, nil
}

// EnumerateExportedKeyPaths returns a list of key paths that can be exported from this keystore.
func (store *KeyStore) EnumerateExportedKeyPaths() ([]string, error) {
	paths := make([]string, 0)

	directories := []string{store.privateKeyDirectory}
	if store.publicKeyDirectory != store.privateKeyDirectory {
		directories = append(directories, store.publicKeyDirectory)
	}

	for i := 0; i < len(directories); i++ {
		files, err := store.fs.ReadDir(directories[i])
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			path := filepath.Join(directories[i], file.Name())
			if file.IsDir() {
				directories = append(directories, path)
			} else {
				paths = append(paths, path)
			}
		}
	}

	return paths, nil
}

// Private and public keys may be stored in two separate directories. We need
// to walk both of them but avoid duplicating ExportedKey entries: key pairs
// must stay as single objects.
//
// We temporarily store ExportedKeys in a map so that we can keep track of
// the keys that we have already seen. Since Go does not allow []byte as
// map keys, we have to get a bit creative.

func (key *ExportedKey) fusedID() string {
	return key.KeyContext.Purpose.String() + string(keystore.GetKeyContextFromContext(key.KeyContext))
}

func (key *ExportedKey) addPathFrom(other *ExportedKey) {
	if other.PublicPath != "" {
		key.PublicPath = other.PublicPath
	}
	if other.PrivatePath != "" {
		key.PrivatePath = other.PrivatePath
	}
	if other.SymmetricPath != "" {
		key.SymmetricPath = other.SymmetricPath
	}
}

// NewExportedSymmetricKey makes an ExportedKey for an unencrypted symmetric key file.
func NewExportedSymmetricKey(symmetricPath string, keyContext keystore.KeyContext) *ExportedKey {
	return &ExportedKey{
		KeyContext:    keyContext,
		SymmetricPath: symmetricPath,
	}
}

// NewExportedPlaintextSymmetricKey makes an ExportedKey for an unencrypted symmetric key file.
func NewExportedPlaintextSymmetricKey(symmetricPath string, keyContext keystore.KeyContext) *ExportedKey {
	return &ExportedKey{
		KeyContext:    keyContext,
		SymmetricPath: symmetricPath,
	}
}

// NewExportedPublicKey makes an ExportedKey for a public key file.
func NewExportedPublicKey(publicPath string, keyContext keystore.KeyContext) *ExportedKey {
	return &ExportedKey{
		KeyContext: keyContext,
		PublicPath: publicPath,
	}
}

// NewExportedPrivateKey makes an ExportedKey for a private key file.
func NewExportedPrivateKey(privatePath string, keyContext keystore.KeyContext) *ExportedKey {
	return &ExportedKey{
		KeyContext:  keyContext,
		PrivatePath: privatePath,
	}
}

// ClassifyExportedKey tells how a key at given path should be exported.
func (*DefaultKeyFileClassifier) ClassifyExportedKey(path string) *ExportedKey {
	filename := filepath.Base(path)

	if filename == SecureLogKeyFilename {
		keyContext := keystore.NewKeyContext(keystore.PurposeAuditLog, []byte(SecureLogKeyFilename))
		return NewExportedSymmetricKey(path, keyContext)
	}

	// Poison key is in ".poison_key" subdirectory, we can't look at filename alone.
	if strings.HasSuffix(path, "/"+getSymmetricKeyName(PoisonKeyFilename)) {
		keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordSymmetricKey, []byte(PoisonKeyFilename))
		return NewExportedSymmetricKey(path, keyContext)
	}

	if strings.HasSuffix(filename, "_hmac") {
		keyContext := keystore.NewClientIDKeyContext(keystore.PurposeSearchHMAC, []byte(strings.TrimSuffix(filename, "_hmac")))
		return NewExportedSymmetricKey(path, keyContext)
	}

	if strings.HasSuffix(filename, "_storage_sym") {
		keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientSymmetricKey, []byte(strings.TrimSuffix(filename, "_storage_sym")))
		return NewExportedSymmetricKey(path, keyContext)
	}

	if strings.HasSuffix(filename, "_zone_sym") {
		keyContext := keystore.NewZoneIDKeyContext(keystore.PurposeStorageZoneSymmetricKey, []byte(strings.TrimSuffix(filename, "_zone_sym")))

		return NewExportedSymmetricKey(path, keyContext)
	}

	// Poison key pairs use PoisonKeyFilename as context for encryption.
	if strings.HasSuffix(path, poisonKeyFilenamePublic) {
		keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordKeyPair, []byte(PoisonKeyFilename))
		return NewExportedPublicKey(path, keyContext)
	}
	if strings.HasSuffix(path, PoisonKeyFilename) {
		keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordKeyPair, []byte(PoisonKeyFilename))
		return NewExportedPrivateKey(path, keyContext)
	}

	if strings.HasSuffix(filename, "_storage.pub") {
		keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientKeyPair, []byte(strings.TrimSuffix(filename, "_storage.pub")))
		return NewExportedPublicKey(path, keyContext)
	}
	if strings.HasSuffix(filename, "_storage") {
		keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientKeyPair, []byte(strings.TrimSuffix(filename, "_storage")))
		return NewExportedPrivateKey(path, keyContext)
	}

	if strings.HasSuffix(filename, "_zone.pub") {
		keyContext := keystore.NewKeyContext(keystore.PurposeStorageZoneKeyPair, []byte(strings.TrimSuffix(filename, "_zone.pub")))
		return NewExportedPublicKey(path, keyContext)
	}

	keyContext := keystore.NewZoneIDKeyContext(keystore.PurposeStorageZoneKeyPair, []byte(strings.TrimSuffix(filename, "_zone")))
	return NewExportedPrivateKey(path, keyContext)

}
