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
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func testGenerateKeyPair(store *KeyStore, t *testing.T) {
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

func testGeneral(store *KeyStore, t *testing.T) {
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

func testGeneratingDataEncryptionKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateDataEncryptionKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	exists, err := utils.FileExists(
		store.GetPrivateKeyFilePath(
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

func checkPath(path string, t *testing.T) {
	exists, err := utils.FileExists(path)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal(fmt.Sprintf("File <%s> doesn't exists", path))
	}
}

func testGenerateServerKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateServerKeys(testID)
	if err != nil {
		t.Fatal(err)
	}

	absPath := store.GetPrivateKeyFilePath(getServerKeyFilename(testID))
	checkPath(absPath, t)
	absPath = store.getPublicKeyFilePath(fmt.Sprintf("%s.pub", getServerKeyFilename(testID)))
	checkPath(absPath, t)
}

func testGenerateTranslatorKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test test id")
	err := store.GenerateTranslatorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	absPath := store.GetPrivateKeyFilePath(getTranslatorKeyFilename(testID))
	checkPath(absPath, t)
	absPath = store.getPublicKeyFilePath(fmt.Sprintf("%s.pub", getTranslatorKeyFilename(testID)))
	checkPath(absPath, t)
}

func testGenerateConnectorKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateConnectorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}

	absPath := store.GetPrivateKeyFilePath(getConnectorKeyFilename(testID))
	checkPath(absPath, t)

	absPath = store.getPublicKeyFilePath(fmt.Sprintf("%s.pub", getConnectorKeyFilename(testID)))
	checkPath(absPath, t)

}

func testReset(store *KeyStore, t *testing.T) {
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
	if err := os.Remove(store.GetPrivateKeyFilePath(getServerKeyFilename(testID))); err != nil {
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

func testGetZonePublicKey(store *KeyStore, t *testing.T) {
	id, binPublic, err := store.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	public, err := store.GetZonePublicKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(binPublic, public.Value) {
		t.Fatal("Incorrect public key value")
	}
}
func testGetClientIDEncryptionPublicKey(store *KeyStore, t *testing.T) {
	id := []byte("some id")
	if err := store.GenerateDataEncryptionKeys(id); err != nil {
		t.Fatal("Can't generate data encryption keys")
	}
	key, err := store.GetClientIDEncryptionPublicKey(id)
	if err != nil {
		t.Fatal("Can't fetch encryption public key by id")
	}
	if key == nil {
		t.Fatal("Unexpected empty public key")
	}
}

func TestFilesystemKeyStore(t *testing.T) {

	privateKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "cache")
	os.MkdirAll(privateKeyDirectory, 0700)
	defer os.RemoveAll(privateKeyDirectory)

	publicKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "public_keys")
	os.MkdirAll(publicKeyDirectory, 0700)
	defer os.RemoveAll(publicKeyDirectory)

	resetKeyFolders := func() {
		os.RemoveAll(privateKeyDirectory)
		os.MkdirAll(privateKeyDirectory, 0700)

		os.RemoveAll(publicKeyDirectory)
		os.MkdirAll(publicKeyDirectory, 0700)
	}

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	generalStore, err := NewFilesystemKeyStore(privateKeyDirectory, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	splitKeysStore, err := NewFilesystemKeyStoreTwoPath(privateKeyDirectory, publicKeyDirectory, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	noCacheKeyStore, err := NewFileSystemKeyStoreWithCacheSize(privateKeyDirectory, encryptor, keystore.WithoutCache)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*KeyStore{generalStore, splitKeysStore, noCacheKeyStore} {
		testGeneral(store, t)
		testGeneratingDataEncryptionKeys(store, t)
		testGenerateConnectorKeys(store, t)
		testGenerateServerKeys(store, t)
		testGenerateTranslatorKeys(store, t)
		testReset(store, t)
		testGenerateKeyPair(store, t)
		testSaveKeypairs(store, t)
		resetKeyFolders()
		testGetZonePublicKey(store, t)
		testGetClientIDEncryptionPublicKey(store, t)
	}
}

func TestFilesystemKeyStoreWithCache(t *testing.T) {
	keyDirectory, err := ioutil.TempDir("", "test_filesystem_store")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(keyDirectory, 0700); err != nil {
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
	if err = store.GenerateDataEncryptionKeys(testID2); err != nil {
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
	store, err = NewFileSystemKeyStoreWithCacheSize(keyDirectory, encryptor, keystore.WithoutCache)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.cache.(keystore.NoCache); !ok {
		t.Fatal("KeyStore wasn't created with NoCache implementation")
	}
}

func TestFilesystemKeyStore_RotateZoneKey(t *testing.T) {
	keyDirectory, err := ioutil.TempDir("", "test_filesystem_store")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(keyDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.RemoveAll(keyDirectory)
	}()
	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	keyStore, err := NewFilesystemKeyStore(keyDirectory, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	id, publicKey, err := keyStore.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := keyStore.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, err := keyStore.RotateZoneKey(id)
	if err != nil {
		t.Fatal(err)
	}
	rotatedPrivateKey, err := keyStore.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(publicKey, newPublic) {
		t.Fatal("Public key the same as rotated")
	}
	if bytes.Equal(rotatedPrivateKey.Value, privateKey.Value) {
		t.Fatal("Private key the same as rotated")
	}
}

func testSaveKeypairs(store *KeyStore, t *testing.T) {
	store.Reset()
	testID := []byte("testid")
	startKeypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	overwritedKeypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	// no matter which function to generate correct filename we will use
	filename := getServerDecryptionKeyFilename(testID)
	if _, err := store.getPrivateKeyByFilename(testID, filename); err == nil {
		t.Fatal("Expected error")
	}
	if err = store.saveKeyPairWithFilename(startKeypair, filename, testID); err != nil {
		t.Fatal(err)
	}
	if privateKey, err := store.getPrivateKeyByFilename(testID, filename); err != nil {
		t.Fatal(err)
	} else {
		if !bytes.Equal(startKeypair.Private.Value, privateKey.Value) {
			t.Fatal("Private key not equal")
		}
	}

	if err = store.saveKeyPairWithFilename(overwritedKeypair, filename, testID); err != nil {
		t.Fatal(err)
	}
	if privateKey, err := store.getPrivateKeyByFilename(testID, filename); err != nil {
		t.Fatal(err)
	} else {
		if !bytes.Equal(overwritedKeypair.Private.Value, privateKey.Value) {
			t.Fatal("Private key not equal")
		}
	}
}
