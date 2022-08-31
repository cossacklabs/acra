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
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestFilesystemKeyStore(t *testing.T) {
	FilesystemKeyStoreTests(&fileStorage{}, t)
}

func FilesystemKeyStoreTests(storage Storage, t *testing.T) {
	testFilesystemKeyStoreBasic(storage, t)
	testFilesystemKeyStoreWithCache(storage, t)
	testFilesystemKeyStoreSymmetricWithCache(storage, t)
	testHistoricalKeyAccess(storage, t)
	testFilesystemKeyStoreWithOnlyCachedData(storage, t)
}

func testGenerateKeyPair(store *KeyStore, t *testing.T) {
	clientID := []byte("some test id")
	// create temp file with random name to use it as not-existed path
	path, err := store.fs.TempFile("test_generate_key_pair", PrivateFileMode)
	if err != nil {
		t.Fatal(err)
	}
	defer store.fs.Remove(path)

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, clientID)
	keypair, err := store.generateKeyPair(path, keyContext)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := store.fs.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// check that returned key != stored on filesystem data
	if bytes.Equal(encryptedKey, keypair.Private.Value) {
		t.Fatal("cache are equal")
	}
}

func testGeneral(store *KeyStore, t *testing.T) {
	id := []byte("non-existent key")
	key, err := store.GetServerDecryptionPrivateKey(id)
	if err == nil {
		t.Fatal("Expected any error")
	}
	if key != nil {
		t.Fatal("Non-expected key")
	}
	err = store.GenerateDataEncryptionKeys(id)
	if err != nil {
		t.Fatal(err)
	}
	key, err = store.GetServerDecryptionPrivateKey(id)
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
	exists, err := store.fs.Exists(
		store.GetPrivateKeyFilePath(
			GetServerDecryptionKeyFilename(testID)))
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Private decryption key doesn't exists")
	}

	exists, err = store.fs.Exists(
		fmt.Sprintf("%s.pub", store.GetPublicKeyFilePath(
			GetServerDecryptionKeyFilename(testID))))
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Public decryption key doesn't exists")
	}
}

func checkPath(store *KeyStore, path string, t *testing.T) {
	exists, err := store.fs.Exists(path)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal(fmt.Sprintf("File <%s> doesn't exists", path))
	}
}

func testGenerateSymKeyUncreatedDir(store *KeyStore, t *testing.T) {
	dir, err := ioutil.TempDir("/tmp", "keys")
	if err != nil {
		t.Fatal(err)
	}
	// ensure we delete dir
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}

	keyContext := keystore.NewEmptyKeyContext([]byte("key"))
	err = store.generateAndSaveSymmetricKey(fmt.Sprintf("%s/%s", dir, "test_id_sym"), keyContext)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(dir)
	if os.IsNotExist(err) {
		t.Fatal("dir should be created")
	}
}

func testKeyStoreCacheOnStart(store *KeyStore, t *testing.T) {
	clientID := []byte("client_id_with_underscore")
	if err := store.GenerateClientIDSymmetricKey(clientID); err != nil {
		log.Fatal(err)
	}

	if err := store.GenerateDataEncryptionKeys(clientID); err != nil {
		log.Fatal(err)
	}

	if err := store.GenerateHmacKey(clientID); err != nil {
		log.Fatal(err)
	}

	if err := store.GenerateLogKey(); err != nil {
		log.Fatal(err)
	}

	if err := store.CacheOnStart(); err != nil {
		log.Fatal(err)
	}

	for _, key := range []string{
		"secure_log_key",
		fmt.Sprintf("%s_storage_sym", clientID),
		fmt.Sprintf("%s_storage", clientID),
		fmt.Sprintf("%s_storage.pub", clientID),
		fmt.Sprintf("%s_hmac", clientID),
	} {
		err := store.fs.Remove(fmt.Sprintf("%s/%s", store.privateKeyDirectory, key))
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
	}

	// read from cache section
	_, err := store.GetClientIDSymmetricKeys(clientID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = store.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = store.GetHMACSecretKey(clientID)
	if err != nil {
		log.Fatal(err)
	}

	_, err = store.GetLogSecretKey()
	if err != nil {
		log.Fatal(err)
	}
}

func testWriteKeyFileUncreatedDir(store *KeyStore, t *testing.T) {
	dir, err := ioutil.TempDir("/tmp", "keys")
	if err != nil {
		t.Fatal(err)
	}
	// ensure we delete dir
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}

	err = store.WriteKeyFile(fmt.Sprintf("%s/%s", dir, "test_id_sym"), []byte("key"), PrivateFileMode)
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(dir)
	if os.IsNotExist(err) {
		t.Fatal("dir should be created")
	}
}

func testGenerateServerKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateServerKeys(testID)
	if err != nil {
		t.Fatal(err)
	}

	absPath := store.GetPrivateKeyFilePath(getServerKeyFilename(testID))
	checkPath(store, absPath, t)
	absPath = store.GetPublicKeyFilePath(fmt.Sprintf("%s.pub", getServerKeyFilename(testID)))
	checkPath(store, absPath, t)
}

func testGenerateTranslatorKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test test id")
	err := store.GenerateTranslatorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	absPath := store.GetPrivateKeyFilePath(getTranslatorKeyFilename(testID))
	checkPath(store, absPath, t)
	absPath = store.GetPublicKeyFilePath(fmt.Sprintf("%s.pub", getTranslatorKeyFilename(testID)))
	checkPath(store, absPath, t)
}

func testGenerateConnectorKeys(store *KeyStore, t *testing.T) {
	testID := []byte("test id")
	err := store.GenerateConnectorKeys(testID)
	if err != nil {
		t.Fatal(err)
	}

	absPath := store.GetPrivateKeyFilePath(getConnectorKeyFilename(testID))
	checkPath(store, absPath, t)

	absPath = store.GetPublicKeyFilePath(fmt.Sprintf("%s.pub", getConnectorKeyFilename(testID)))
	checkPath(store, absPath, t)

}

func testGeneratePoissonSymmetricKey(store *KeyStore, t *testing.T) {
	err := store.GeneratePoisonSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := store.GetPrivateKeyFilePath(getSymmetricKeyName(PoisonKeyFilename))
	exists, err := store.fs.Exists(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Poisson symmetic key doesn't exists")
	}
}

func testGeneratePoissonKeyPair(store *KeyStore, t *testing.T) {
	err := store.GeneratePoisonKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privatePath := store.GetPrivateKeyFilePath(PoisonKeyFilename)
	exists, err := store.fs.Exists(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Poisson private key doesn't exists")
	}
	publicPath := store.GetPublicKeyFilePath(PoisonKeyFilename + ".pub")
	exists, err = store.fs.Exists(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Poisson public key doesn't exists")
	}
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
	if err := store.fs.Remove(store.GetPrivateKeyFilePath(getServerKeyFilename(testID))); err != nil {
		t.Fatal(err)
	}
	if err := store.fs.Remove(fmt.Sprintf("%s.pub", store.GetPublicKeyFilePath(getServerKeyFilename(testID)))); err != nil {
		t.Fatal(err)
	}
	if err := store.fs.Remove(fmt.Sprintf("%s.pub", store.GetPublicKeyFilePath(getTranslatorKeyFilename(testID)))); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetPrivateKey(testID); err == nil {
		t.Fatal("Expected error on fetching cleared key")
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

func testGetSymmetricKey(store *KeyStore, t *testing.T) {
	// Insert one clientID key, expect to get it
	testClientID := []byte("client1")
	if err := store.GenerateClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}

	// Insert multiple clientID keys, expect to get 0th one
	testClientID = []byte("client2")
	if err := store.GenerateClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateClientIDSymmetricKey(testClientID); err != nil {
		t.Fatal(err)
	}
	encryptionKeys, err := store.GetClientIDSymmetricKeys(testClientID)
	if err != nil {
		t.Fatal(err)
	}
	encryptionKey, err := store.GetClientIDSymmetricKey(testClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encryptionKey, encryptionKeys[0]) {
		t.Fatal("store.GetClientIDSymmetricKey() did not return 0th key")
	}
}

func testGetPoisonSymmetricKey(store *KeyStore, t *testing.T) {
	poisonKey1, err := store.GetPoisonSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(poisonKey1) != keystore.SymmetricKeyLength {
		t.Fatalf("GetPoisonSymmetricKey() returned encrypted key (%d bytes, expected %d)\n", len(poisonKey1), keystore.SymmetricKeyLength)
	}

	poisonKey2, err := store.GetPoisonSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(poisonKey2) != keystore.SymmetricKeyLength {
		t.Fatalf("GetPoisonSymmetricKey() returned encrypted key (%d bytes, expected %d)\n", len(poisonKey2), keystore.SymmetricKeyLength)
	}

	if !bytes.Equal(poisonKey1, poisonKey2) {
		t.Fatal("Two calls to GetPoisonSymmetricKey() returned different keys")
	}
}

func testGetPoisonKeyPair(store *KeyStore, t *testing.T) {
	keypair1, err := store.GetPoisonKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	keypair2, err := store.GetPoisonKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(keypair1.Public.Value, keypair2.Public.Value) {
		t.Fatal("Two calls to GetPoisonKeyPair() returned different public keys")
	}

	if !bytes.Equal(keypair1.Private.Value, keypair2.Private.Value) {
		t.Fatal("Two calls to GetPoisonKeyPair() returned different private keys")
	}
}

func testFilesystemKeyStoreBasic(storage Storage, t *testing.T) {
	privateKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "cache")
	storage.MkdirAll(privateKeyDirectory, 0700)
	defer storage.RemoveAll(privateKeyDirectory)

	publicKeyDirectory := fmt.Sprintf(".%s%s", string(filepath.Separator), "public_keys")
	storage.MkdirAll(publicKeyDirectory, 0700)
	defer storage.RemoveAll(publicKeyDirectory)

	resetKeyFolders := func() {
		storage.RemoveAll(privateKeyDirectory)
		storage.MkdirAll(privateKeyDirectory, 0700)

		storage.RemoveAll(publicKeyDirectory)
		storage.MkdirAll(publicKeyDirectory, 0700)
	}
	resetKeyFolders()

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	generalStore, err := NewCustomFilesystemKeyStore().
		KeyDirectory(privateKeyDirectory).
		Encryptor(encryptor).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	splitKeysStore, err := NewCustomFilesystemKeyStore().
		KeyDirectories(privateKeyDirectory, publicKeyDirectory).
		Encryptor(encryptor).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	noCacheKeyStore, err := NewCustomFilesystemKeyStore().
		KeyDirectories(privateKeyDirectory, publicKeyDirectory).
		Encryptor(encryptor).
		CacheSize(keystore.WithoutCache).
		Storage(storage).
		Build()
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
		testGenerateSymKeyUncreatedDir(store, t)
		testWriteKeyFileUncreatedDir(store, t)
		testGetClientIDEncryptionPublicKey(store, t)
		testGetSymmetricKey(store, t)

		testGeneratePoissonSymmetricKey(store, t)
		testGeneratePoissonKeyPair(store, t)
		testGetPoisonSymmetricKey(store, t)
	}
}

func testFilesystemKeyStoreSymmetricWithCache(storage Storage, t *testing.T) {
	keyDirectory, err := storage.TempDir("test_filesystem_store", keyDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.RemoveAll(keyDirectory)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		// set 3 because 1 key and 2 GetHistoricalFileNames call that cached too
		CacheSize(3).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	// create some key
	testID := []byte("test id")
	if err := store.GenerateClientIDSymmetricKey(testID); err != nil {
		t.Fatal(err)
	}
	// load and save in cache
	_, err = store.GetClientIDSymmetricKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	testID2 := []byte("test id 2")
	// create one more key that shouldn't saved in cache with 1 size
	if err = store.GenerateClientIDSymmetricKey(testID2); err != nil {
		t.Fatal(err)
	}
	// load and save in cache. it must drop previous key from cache
	keys, err := store.GetClientIDSymmetricKeys(testID2)
	if err != nil {
		t.Fatal(err)
	}
	filenames, err := store.GetHistoricalPrivateKeyFilenames(getClientIDSymmetricKeyName(testID))
	if err != nil {
		t.Fatal(err)
	}
	if len(filenames) != 1 {
		t.Fatal("Unexpected amount of filenames")
	}
	// check that previous value was dropped
	value, ok := store.cache.Get(filenames[0])
	if ok {
		t.Fatal("Value wasn't expected")
	}
	if value != nil {
		t.Fatal("Value wasn't expected")
	}
	filenames, err = store.GetHistoricalPrivateKeyFilenames(getClientIDSymmetricKeyName(testID2))
	if err != nil {
		t.Fatal(err)
	}
	if len(filenames) != 1 {
		t.Fatal("Unexpected amount of filenames")
	}
	// check that new values is what we expect: encrypted key
	value, ok = store.cache.Get(filenames[0])
	if !ok {
		t.Fatal("Expected key in result")
	}

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientSymmetricKey, testID2)
	decrypted, err := store.cacheEncryptor.Decrypt(context.Background(), value, keyContext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, keys[0]) {
		t.Fatal("Expected correct key in result")
	}

	// check that store created with empty cache
	store, err = NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		CacheSize(keystore.WithoutCache).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.cache.(keystore.NoCache); !ok {
		t.Fatal("KeyStore wasn't created with NoCache implementation")
	}
}

func testFilesystemKeyStoreWithCache(storage Storage, t *testing.T) {
	keyDirectory, err := storage.TempDir("test_filesystem_store", keyDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.RemoveAll(keyDirectory)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		CacheSize(1).
		Storage(storage).
		Build()
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
	value, ok := store.cache.Get(GetServerDecryptionKeyFilename(testID))
	if ok {
		t.Fatal("Value wasn't expected")
	}
	if value != nil {
		t.Fatal("Value wasn't expected")
	}

	// check that new values is what we expect: encrypted key
	value, ok = store.cache.Get(GetServerDecryptionKeyFilename(testID2))
	if !ok {
		t.Fatal("Expected key in result")
	}

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientSymmetricKey, testID2)
	decrypted, err := store.cacheEncryptor.Decrypt(context.Background(), value, keyContext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, privateKey2.Value) {
		t.Fatal("Expected correct key in result")
	}

	// check that store created with empty cache
	store, err = NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		CacheSize(keystore.WithoutCache).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.cache.(keystore.NoCache); !ok {
		t.Fatal("KeyStore wasn't created with NoCache implementation")
	}
}

func testFilesystemKeyStoreWithOnlyCachedData(storage Storage, t *testing.T) {
	keyDirectory, err := storage.TempDir("test_filesystem_store", keyDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.RemoveAll(keyDirectory)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		CacheSize(keystore.InfiniteCacheSize).
		Storage(storage).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	// generate all kind of keys. Generate twice if keys support rotation to check that cached all keys
	testID := []byte("test id")
	if err := store.GenerateDataEncryptionKeys(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateDataEncryptionKeys(testID); err != nil {
		t.Fatal(err)
	}

	if err := store.GenerateHmacKey(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateLogKey(); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateClientIDSymmetricKey(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GenerateClientIDSymmetricKey(testID); err != nil {
		t.Fatal(err)
	}
	if err := store.GeneratePoisonSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	if err := store.GeneratePoisonSymmetricKey(); err != nil {
		t.Fatal(err)
	}
	if err := store.GeneratePoisonKeyPair(); err != nil {
		t.Fatal(err)
	}
	if err := store.GeneratePoisonKeyPair(); err != nil {
		t.Fatal(err)
	}
	// fetch keys once to cache backed up keys. due to implementation backed up keys don't stored in cache
	// and put there only after first fetching operation
	_, err = store.GetServerDecryptionPrivateKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetClientIDEncryptionPublicKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetHMACSecretKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetLogSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetClientIDSymmetricKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetPoisonSymmetricKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.GetPoisonPrivateKeys()
	if err != nil {
		t.Fatal(err)
	}
	// we expect that all keys put in cache after generation. so delete them from storage
	if err := storage.RemoveAll(keyDirectory); err != nil {
		t.Fatal(err)
	}

	// load and save in cache
	privateECKey, err := store.GetServerDecryptionPrivateKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	if len(privateECKey) != 2 {
		t.Fatal("PrivateEC keys not cached")
	}
	hmacKey, err := store.GetHMACSecretKey(testID)
	if err != nil {
		t.Fatal(err)
	}
	if hmacKey == nil {
		t.Fatal("Hmac key not cached")
	}
	logKey, err := store.GetLogSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	if logKey == nil {
		t.Fatal("log key not cached")
	}

	symKeys, err := store.GetClientIDSymmetricKeys(testID)
	if err != nil {
		t.Fatal(err)
	}
	if len(symKeys) != 2 {
		t.Fatal("ClientID sym keys not cached")
	}

	symKeys, err = store.GetPoisonSymmetricKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(symKeys) != 2 {
		t.Fatal("Poison sym keys not cached")
	}

	asymKeys, err := store.GetPoisonPrivateKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(asymKeys) != 2 {
		t.Fatal("Poison asym keys not cached")
	}
	keyPair, err := store.GetPoisonKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if keyPair == nil {
		t.Fatal("Poison keypair not cached")
	}
}

func testSaveKeypairs(store *KeyStore, t *testing.T) {
	store.Reset()
	testID := []byte("testid")
	startKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	overwritedKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	// no matter which function to generate correct filename we will use
	filename := GetServerDecryptionKeyFilename(testID)
	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, testID)
	if _, err := store.getPrivateKeyByFilename(filename, keyContext); err == nil {
		t.Fatal("Expected error")
	}
	if err = store.SaveKeyPairWithFilename(startKeypair, filename, keyContext); err != nil {
		t.Fatal(err)
	}
	if privateKey, err := store.getPrivateKeyByFilename(filename, keyContext); err != nil {
		t.Fatal(err)
	} else {
		if !bytes.Equal(startKeypair.Private.Value, privateKey.Value) {
			t.Fatal("Private key not equal")
		}
	}

	if err = store.SaveKeyPairWithFilename(overwritedKeypair, filename, keyContext); err != nil {
		t.Fatal(err)
	}
	if privateKey, err := store.getPrivateKeyByFilename(filename, keyContext); err != nil {
		t.Fatal(err)
	} else {
		if !bytes.Equal(overwritedKeypair.Private.Value, privateKey.Value) {
			t.Fatal("Private key not equal")
		}
	}
}

func TestFilesystemKeyStoreExport(t *testing.T) {
	// Prepare filesystem directory
	keyDirectory, err := ioutil.TempDir(os.TempDir(), "test_filesystem_store")
	if err != nil {
		t.Fatalf("failed to create key directory: %v", err)
	}
	if err = os.Chmod(keyDirectory, 0700); err != nil {
		t.Fatalf("failed to chmod key directory: %v", err)
	}
	defer func() {
		os.RemoveAll(keyDirectory)
	}()
	publicKeys := filepath.Join(keyDirectory, "public")
	privateKeys := filepath.Join(keyDirectory, "private")

	// Prepare keystore
	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("test key"))
	if err != nil {
		t.Fatalf("failed to initialize encryptor: %v", err)
	}

	keyStore, err := NewFilesystemKeyStoreTwoPath(privateKeys, publicKeys, encryptor)
	if err != nil {
		t.Fatalf("failed to initialize keystore: %v", err)
	}

	// Prepare various keys for testing.
	clientID := []byte("Alice Liddell")

	err = keyStore.GenerateDataEncryptionKeys(clientID)
	if err != nil {
		t.Fatalf("GenerateDataEncryptionKeys() failed: %v", err)
	}
	storagePublicKey, err := keyStore.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		t.Fatalf("GetClientIDEncryptionPublicKey() failed: %v", err)
	}
	storagePrivateKey, err := keyStore.GetServerDecryptionPrivateKey(clientID)
	if err != nil {
		t.Fatalf("GetServerDecryptionPrivateKey() failed: %v", err)
	}
	if err = keyStore.GeneratePoisonKeyPair(); err != nil {
		t.Fatalf("GeneratePoisonKeyPair() failed: %v", err)
	}

	poisonKeyPair, err := keyStore.GetPoisonKeyPair()
	if err != nil {
		t.Fatalf("GetPoisonKeyPair() failed: %v", err)
	}

	// Test setup complete, now we can finally verify exporting.
	exportedKeys, err := EnumerateExportedKeys(keyStore)
	if err != nil {
		t.Errorf("EnumerateExportedKeys() failed: %v", err)
	}

	seenPoisonKeyPair := false
	seenStorageClientKeyPair := false

	for i := range exportedKeys {
		switch exportedKeys[i].KeyContext.Purpose {
		case keystore.PurposePoisonRecordKeyPair:
			seenPoisonKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(poisonKeyPair.Public.Value, publicKey.Value) {
				t.Error("incorrect poison record public key value")
			}
			if !bytes.Equal(poisonKeyPair.Private.Value, privateKey.Value) {
				t.Error("incorrect poison record private key value")
			}
		case keystore.PurposeStorageClientKeyPair:
			seenStorageClientKeyPair = true
			publicKey, err := keyStore.ExportPublicKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPublicKey() failed: %v", err)
			}
			privateKey, err := keyStore.ExportPrivateKey(exportedKeys[i])
			if err != nil {
				t.Errorf("ExportPrivateKey() failed: %v", err)
			}
			if !bytes.Equal(storagePublicKey.Value, publicKey.Value) {
				t.Error("incorrect client storage public key value")
			}
			if !bytes.Equal(storagePrivateKey.Value, privateKey.Value) {
				t.Error("incorrect client storage private key value")
			}
		default:
			t.Errorf("unknow key purpose: %s", exportedKeys[i].KeyContext.Purpose)
		}
	}

	if !seenPoisonKeyPair {
		t.Error("poison record key pair not exported")
	}
	if !seenStorageClientKeyPair {
		t.Error("storage key for client not expoted")
	}
}

func testHistoricalKeyAccess(storage Storage, t *testing.T) {
	keyDirectory, err := storage.TempDir("test_filesystem_store", keyDirMode)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.RemoveAll(keyDirectory)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}

	keyStore, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDirectory).
		Encryptor(encryptor).
		Storage(storage).
		CacheSize(keystore.WithoutCache).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	id := []byte("some id")
	err = keyStore.GenerateClientIDSymmetricKey(id)
	if err != nil {
		t.Fatal(err)
	}
	key1, err := keyStore.GetClientIDSymmetricKey(id)
	if err != nil {
		t.Fatal(err)
	}
	err = keyStore.GenerateClientIDSymmetricKey(id)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := keyStore.GetClientIDSymmetricKey(id)
	if err != nil {
		t.Fatal(err)
	}
	allPrivateKeys, err := keyStore.GetClientIDSymmetricKeys(id)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("rotated key should not stay the same")
	}
	if len(allPrivateKeys) != 2 {
		t.Errorf("incorrect total number of keys: %v", len(allPrivateKeys))
	} else {
		// From newest to oldest
		if !bytes.Equal(allPrivateKeys[0], key2) {
			t.Error("incorrect current private key value")
		}
		if !bytes.Equal(allPrivateKeys[1], key1) {
			t.Error("incorrect previous private key value")
		}
	}
}

// BenchmarkHistoricalPathsSerialization compare simple way of serialization []string into []byte with strings.[Split|Join] and msgpack
// Example of benchmarks to see comparison how msgpack faster simple join/split operations with strings
// goos: linux
// goarch: amd64
// pkg: github.com/cossacklabs/acra/keystore/filesystem
// cpu: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz
// BenchmarkHistoricalPathsSerialization
// BenchmarkHistoricalPathsSerialization/serialize_with_strings.Split/strings.Join
// BenchmarkHistoricalPathsSerialization/serialize_with_strings.Split/strings.Join-12         	 1000000	      1055 ns/op
// BenchmarkHistoricalPathsSerialization/serialize_with_msgpack
// BenchmarkHistoricalPathsSerialization/serialize_with_msgpack-12                            	1000000000	         0.0000044 ns/op
func BenchmarkHistoricalPathsSerialization(b *testing.B) {
	values := []string{
		"some key 1",
		"some key 2",
		"some key 3",
		"some key 4",
		"some key 5",
	}
	sep := string([]byte{0})
	cacheByJoin := func(paths []string) []byte {
		return []byte(strings.Join(paths, sep))
	}
	getCacheBySplit := func(value []byte) []string {
		return strings.Split(string(value), sep)
	}

	b.Run("serialize with strings.Split/strings.Join", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cached := cacheByJoin(values)
			stringsValue := getCacheBySplit(cached)
			reflect.DeepEqual(stringsValue, values)
		}
	})
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	ks, err := NewCustomFilesystemKeyStore().Encryptor(&dummyEncryptor{}).KeyDirectory(tmpDir).Build()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("serialize with msgpack", func(b *testing.B) {
		if err := ks.cacheHistoricalPrivateKeyFilenames("id", values); err != nil {
			b.Fatal(err)
		}
		paths, err := ks.getCachedHistoricalPrivateKeyFilenames("id")
		if err != nil {
			b.Fatal(err)
		}
		reflect.DeepEqual(paths, values)
	})
}

func TestKeyStore_GetPoisonKeyPair(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := keystore.NewSCellKeyEncryptor([]byte(`some key`))
	if err != nil {
		t.Fatal(err)
	}
	keyStore, err := NewFilesystemKeyStore(tmpDir, encryptor)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("Check empty cache before generation", func(t *testing.T) {
		_, ok := keyStore.cache.Get(PoisonKeyFilename)
		if ok {
			t.Fatal("Unexpected cached poison private key")
		}
		_, ok = keyStore.cache.Get(poisonKeyFilenamePublic)
		if ok {
			t.Fatal("Unexpected cached poison public key")
		}
	})

	t.Run("Check keys don't generate on Get", func(t *testing.T) {
		_, err := keyStore.GetPoisonKeyPair()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}

		_, err = keyStore.GetPoisonSymmetricKey()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}

		_, err = keyStore.GetPoisonPrivateKeys()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}
		_, err = keyStore.GetPoisonSymmetricKeys()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}
	})

	if err = keyStore.GeneratePoisonKeyPair(); err != nil {
		t.Fatal(err)
	}

	keyPair, err := keyStore.GetPoisonKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("Check caching keys after generation and property that private key encrypted", func(t *testing.T) {
		privateKey, ok := keyStore.cache.Get(PoisonKeyFilename)
		if !ok {
			t.Fatal("Private key wasn't cached")
		}
		if bytes.Equal(privateKey, keyPair.Private.Value) {
			t.Fatal("Cached private key wasn't encrypted and equal to generated raw keypair")
		}
		publicKey, ok := keyStore.cache.Get(poisonKeyFilenamePublic)
		if !ok {
			t.Fatal("Public key wasn't cached")
		}
		if !bytes.Equal(keyPair.Public.Value, publicKey) {
			t.Fatal("Cached public key not equal to raw key")
		}
	})
	t.Run("Check reading keys from the cache after purging keystore folder", func(t *testing.T) {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatal(err)
		}
		keyPair2, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(keyPair2.Public.Value, keyPair.Public.Value) {
			t.Fatal("Took unexpected new keypair's public key")
		}
		if !bytes.Equal(keyPair2.Private.Value, keyPair.Private.Value) {
			t.Fatal("Took unexpected new keypair's private key")
		}
	})
}

func getKeystore() (*KeyStore, string, error) {
	keyDir, err := ioutil.TempDir(os.TempDir(), "testKeystore")

	if err != nil {
		return nil, "", err
	}

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		return nil, "", err
	}

	keyStore, err := NewCustomFilesystemKeyStore().
		KeyDirectory(keyDir).
		Encryptor(encryptor).
		Storage(&fileStorage{}).
		Build()
	return keyStore, keyDir, err
}

func TestPoisonKeyGeneration(t *testing.T) {
	keyStore, path, err := getKeystore()
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(path)

	t.Run("Poison keys don't generate on Get", func(t *testing.T) {
		_, err := keyStore.GetPoisonKeyPair()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}

		_, err = keyStore.GetPoisonSymmetricKey()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}

		_, err = keyStore.GetPoisonPrivateKeys()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}
		_, err = keyStore.GetPoisonSymmetricKeys()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}
	})

	t.Run("Poison keys can be generated", func(t *testing.T) {
		err := keyStore.GeneratePoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		err = keyStore.GeneratePoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Poison key are generated successfully", func(t *testing.T) {
		keyPair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		symKey, err := keyStore.GetPoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(symKey) != keystore.SymmetricKeyLength {
			t.Fatalf("Wrong length: expected %d, but got %d", keystore.SymmetricKeyLength, len(symKey))
		}

		privateKeys, err := keyStore.GetPoisonPrivateKeys()
		if err != nil {
			t.Fatal(err)
		}
		if len(privateKeys) != 1 {
			t.Fatalf("Wrong number of private keys: expected 1, but got %d", len(privateKeys))
		}
		if !bytes.Equal(privateKeys[0].Value, keyPair.Private.Value) {
			t.Fatal("Private keys are not equal")
		}

		symKeys, err := keyStore.GetPoisonSymmetricKeys()
		if err != nil {
			t.Fatal(err)
		}
		if len(symKeys) != 1 {
			t.Fatalf("Wrong number of symmetric keys: expected 1, but got %d", len(symKeys))
		}
		if !bytes.Equal(symKeys[0], symKey) {
			t.Fatal("Symmetric keys are not equal")
		}
	})

	t.Run("Poison keys can be rotated", func(t *testing.T) {
		// Save old keys
		oldKeyPair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		oldSymKey, err := keyStore.GetPoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		// Generate new ones
		err = keyStore.GeneratePoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		err = keyStore.GeneratePoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		// TODO: for some reasons, new keys are not added to the cache. This
		// resuts in a retrieval of wrong key.
		// In theory, that's not a problem for Acra, because keys are generated
		// and used by different entities (keymaker and Acra-server), but still
		// could be an issue, if someone wants to rotate keys on the fly.
		// .CacheSize(0) don't help
		keyStore.cache.Clear()

		// Retrieve new ones
		newKeyPair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		newSymKey, err := keyStore.GetPoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		privateKeys, err := keyStore.GetPoisonPrivateKeys()
		if err != nil {
			t.Fatal(err)
		}

		symKeys, err := keyStore.GetPoisonSymmetricKeys()
		if err != nil {
			t.Fatal(err)
		}

		// Compare

		if bytes.Equal(oldKeyPair.Private.Value, newKeyPair.Private.Value) {
			t.Fatal("Private keys are equal after rotation")
		}

		if bytes.Equal(oldKeyPair.Public.Value, newKeyPair.Public.Value) {
			t.Fatal("Public keys are equal after rotation")
		}

		if bytes.Equal(oldSymKey, newSymKey) {
			t.Fatal("Symmetric keys are equal after rotation")
		}

		if len(privateKeys) != 2 {
			t.Fatalf("Wrong number of private keys: expected 2, but got %d", len(privateKeys))
		}
		if len(symKeys) != 2 {
			t.Fatalf("Wrong number of symmetric keys: expected 2, but got %d", len(symKeys))
		}

		if !bytes.Equal(privateKeys[0].Value, newKeyPair.Private.Value) {
			t.Fatal("First private key should be the newest one")
		}

		if !bytes.Equal(privateKeys[1].Value, oldKeyPair.Private.Value) {
			t.Fatal("First private key should be the oldest one")
		}

		if !bytes.Equal(privateKeys[0].Value, newKeyPair.Private.Value) {
			t.Fatal("First private key should be the newest one")
		}

		if !bytes.Equal(symKeys[0], newSymKey) {
			t.Fatal("First symmetric key should be the newest one")
		}

		if !bytes.Equal(symKeys[1], oldSymKey) {
			t.Fatal("Second symmetric key should be the oldest one")
		}
	})
}

const (
	clientID  = "cossack"
	dataEncID = "cossack-data-enc"
	hmacEncID = "cossack-hmac"
)

func generateEveryKey(keyStore *KeyStore, t *testing.T) {
	if err := keyStore.GenerateClientIDSymmetricKey([]byte(clientID)); err != nil {
		t.Fatal(err)
	}
	if err := keyStore.GenerateDataEncryptionKeys([]byte(clientID)); err != nil {
		t.Fatal(err)
	}
	if err := keyStore.GenerateHmacKey([]byte(hmacEncID)); err != nil {
		t.Fatal(err)
	}
	if err := keyStore.GenerateLogKey(); err != nil {
		t.Fatal(err)
	}
	if err := keyStore.GeneratePoisonKeyPair(); err != nil {
		t.Fatal(err)
	}
	if err := keyStore.GeneratePoisonSymmetricKey(); err != nil {
		t.Fatal(err)
	}
}

func getAllExpectedKeys() []keystore.KeyDescription {
	expectedKeys := []keystore.KeyDescription{
		{ID: "poison_key", Purpose: keystore.PurposePoisonRecordKeyPair},
		{ID: "poison_key.pub", Purpose: keystore.PurposePoisonRecordKeyPair},
		{ID: "poison_key_sym", Purpose: keystore.PurposePoisonRecordSymmetricKey},
		{ID: "cossack-hmac_hmac", Purpose: keystore.PurposeSearchHMAC, ClientID: []byte(hmacEncID)},
		{ID: "cossack_storage", Purpose: keystore.PurposeStorageClientPrivateKey, ClientID: []byte(clientID)},
		{ID: "cossack_storage.pub", Purpose: keystore.PurposeStorageClientPublicKey, ClientID: []byte(clientID)},
		{ID: "cossack_storage_sym", Purpose: keystore.PurposeStorageClientSymmetricKey, ClientID: []byte(clientID)},
		{ID: "secure_log_key", Purpose: keystore.PurposeAuditLog},
	}
	// sort to compare consistently
	sort.Slice(expectedKeys, func(i, j int) bool {
		return expectedKeys[i].ID < expectedKeys[j].ID
	})
	return expectedKeys
}

func TestListKeysSamePaths(t *testing.T) {
	keyStore, path, err := getKeystore()
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(path)

	generateEveryKey(keyStore, t)

	all, err := keyStore.ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].ID < all[j].ID
	})

	buff := bytes.NewBuffer([]byte{})

	expectedKeys := getAllExpectedKeys()
	keystore.PrintKeysTable(expectedKeys, buff)
	expected := buff.String()

	buff.Reset()
	keystore.PrintKeysTable(all, buff)
	found := buff.String()

	fmt.Fprintln(os.Stderr, "=> Expected Keys")
	fmt.Fprintln(os.Stderr, expected)
	fmt.Fprintln(os.Stderr, "=> Actual Keys")
	fmt.Fprintln(os.Stderr, found)

	if expected != found {
		t.Fatal("lists are different")
	}
}

func TestListKeysDifferentPaths(t *testing.T) {
	keyPrivateDir, err := ioutil.TempDir(os.TempDir(), "private")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(keyPrivateDir)

	keyPublicDir, err := ioutil.TempDir(os.TempDir(), "public")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(keyPublicDir)

	encryptor, err := keystore.NewSCellKeyEncryptor([]byte("some key"))
	if err != nil {
		t.Fatal(err)
	}

	keyStore, err := NewFilesystemKeyStoreTwoPath(keyPrivateDir, keyPublicDir, encryptor)
	if err != nil {
		t.Fatal(err)
	}

	generateEveryKey(keyStore, t)

	all, err := keyStore.ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].ID < all[j].ID
	})

	buff := bytes.NewBuffer([]byte{})

	expectedKeys := getAllExpectedKeys()
	keystore.PrintKeysTable(expectedKeys, buff)
	expected := buff.String()

	buff.Reset()
	keystore.PrintKeysTable(all, buff)
	found := buff.String()

	fmt.Fprintln(os.Stderr, "=> Expected Keys")
	fmt.Fprintln(os.Stderr, expected)
	fmt.Fprintln(os.Stderr, "=> Actual Keys")
	fmt.Fprintln(os.Stderr, found)

	if expected != found {
		t.Fatal("lists are different")
	}
}
