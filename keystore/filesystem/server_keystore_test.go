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
package filesystem

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func testGenerateKeyPair(store *FilesystemKeyStore, t *testing.T) {
	clientID := []byte("some test id")
	file, err := ioutil.TempFile("", "test_generate_key_pair")
	if err != nil {
		t.Fatal(err)
	}
	// create temp file with random name to use it as not-existed path
	path := file.Name()
	file.Close()
	defer os.Remove(path)
	keypair, err := store.generateKeyPair(path, clientID)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// check that returned key != stored on filesystem data
	if bytes.Equal(encryptedKey, keypair.Private.Value) {
		t.Fatal("cache are equal")
	}
}

func testGeneral(store *FilesystemKeyStore, t *testing.T) {
	if store.HasZonePrivateKey([]byte("non-existent key")) {
		t.Fatal("Expected false on non-existent key")
	}
	key, err := store.GetZonePrivateKey([]byte("non-existent key"))
	if err == nil {
		t.Fatal("Expected any error")
	}
	if key != nil {
		t.Fatal("Non-expected key")
	}
	id, _, err := store.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	if !store.HasZonePrivateKey(id) {
		t.Fatal("Expected true on existed id")
	}
	key, err = store.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("Expected private key")
	}
}

func testGeneratingDataEncryptionKeys(store *FilesystemKeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateDataEncryptionKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	exists, err := utils.FileExists(
		store.getPrivateKeyFilePath(
			getServerDecryptionKeyFilename(testID)))
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Private decryption key doesn't exists")
	}

	exists, err = utils.FileExists(
		fmt.Sprintf("%s.pub", store.getPublicKeyFilePath(
			getServerDecryptionKeyFilename(testID))))
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Public decryption key doesn't exists")
	}
}

func testGenerateServerKeys(store *FilesystemKeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateServerKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	expectedPaths := []string{
		getServerKeyFilename(testID),
		fmt.Sprintf("%s.pub", getServerKeyFilename(testID)),
	}
	for _, name := range expectedPaths {
		absPath := store.getPrivateKeyFilePath(name)
		exists, err := utils.FileExists(absPath)
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatal(fmt.Sprintf("File <%s> doesn't exists", absPath))
		}
	}
}

func testGenerateTranslatorKeys(store *FilesystemKeyStore, t *testing.T) {
	testID := []byte("test test id")
	err := store.GenerateTranslatorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	expectedPaths := []string{
		getTranslatorKeyFilename(testID),
		fmt.Sprintf("%s.pub", getTranslatorKeyFilename(testID)),
	}
	for _, name := range expectedPaths {
		absPath := store.getPrivateKeyFilePath(name)
		exists, err := utils.FileExists(absPath)
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatal(fmt.Sprintf("File <%s> doesn't exists", absPath))
		}
	}
}

func testGenerateConnectorKeys(store *FilesystemKeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateConnectorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	expectedPaths := []string{
		getConnectorKeyFilename(testID),
		fmt.Sprintf("%s.pub", getConnectorKeyFilename(testID)),
	}
	for _, name := range expectedPaths {
		absPath := store.getPrivateKeyFilePath(name)
		exists, err := utils.FileExists(absPath)
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatal(fmt.Sprintf("File <%s> doesn't exists", absPath))
		}
	}
}

func testReset(store *FilesystemKeyStore, t *testing.T) {
	testID := []byte("some test id")
	if err := store.GenerateServerKeys(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateTranslatorKeys(testID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPrivateKey(testID); err != nil {
		t.Fatal(err)
	}
	store.Reset()
	if err := os.Remove(store.getPrivateKeyFilePath(getServerKeyFilename(testID))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fmt.Sprintf("%s.pub", store.getPublicKeyFilePath(getServerKeyFilename(testID)))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fmt.Sprintf("%s.pub", store.getPublicKeyFilePath(getTranslatorKeyFilename(testID)))); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetPrivateKey(testID); err == nil {
		t.Fatal("Expected error on fetching cleared key")
	}
}

func TestFilesystemKeyStore(t *testing.T) {
	privateKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "cache")
	os.MkdirAll(privateKeyDirectory, 0700)
	defer func() {
		os.RemoveAll(privateKeyDirectory)
	}()

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "public_keys")
	os.MkdirAll(publicKeyDirectory, 0700)
	defer func() {
		os.RemoveAll(publicKeyDirectory)
	}()
	generalStore, err := NewFilesystemKeyStore(privateKeyDirectory, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	splitKeysStore, err := NewFilesystemKeyStoreTwoPath(privateKeyDirectory, publicKeyDirectory, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	noCacheKeyStore, err := NewFileSystemKeyStoreWithCacheSize(privateKeyDirectory, encryptor, keystore.NO_CACHE)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*FilesystemKeyStore{generalStore, splitKeysStore, noCacheKeyStore} {
		testGeneral(store, t)
		testGeneratingDataEncryptionKeys(store, t)
		testGenerateConnectorKeys(store, t)
		testGenerateServerKeys(store, t)
		testGenerateTranslatorKeys(store, t)
		testReset(store, t)
		testGenerateKeyPair(store, t)
	}
}

func TestFilesystemKeyStoreWithCache(t *testing.T) {
	keyDirectory, err := ioutil.TempDir("", "test_filesystem_store")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.RemoveAll(keyDirectory)
	}()

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFileSystemKeyStoreWithCacheSize(keyDirectory, encryptor, 1)
	if err != nil {
		t.Fatal(err)
	}
	// create some key
	testID := []byte("test id")
	if err := store.GenerateDataEncryptionKeys(testID); err != nil {
		t.Fatal(err)
	}
	// load and save in cache
	_, err = store.GetServerDecryptionPrivateKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	testID2 := []byte("test id 2")
	// create one more key that shouldn't saved in cache with 1 size
	if err := store.GenerateDataEncryptionKeys(testID2); err != nil {
		t.Fatal(err)
	}
	// load and save in cache. it must drop previous key from cache
	privateKey2, err := store.GetServerDecryptionPrivateKey(testID2)
	if err != nil {
		t.Fatal(err)
	}

	// check that previous value was dropped
	value, ok := store.cache.Get(getServerDecryptionKeyFilename(testID))
	if ok {
		t.Fatal("Value wasn't expected")
	}
	if value != nil {
		t.Fatal("Value wasn't expected")
	}

	// check that new values is what we expect: encrypted key
	value, ok = store.cache.Get(getServerDecryptionKeyFilename(testID2))
	if !ok {
		t.Fatal("Expected key in result")
	}
	decrypted, err := encryptor.Decrypt(value, testID2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, privateKey2.Value) {
		t.Fatal("Expected correct key in result")
	}

	// check that store created with empty cache
	store, err = NewFileSystemKeyStoreWithCacheSize(keyDirectory, encryptor, keystore.NO_CACHE)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.cache.(keystore.NoCache); !ok {
		t.Fatal("KeyStore wasn't created with NoCache implementation")
	}
}
