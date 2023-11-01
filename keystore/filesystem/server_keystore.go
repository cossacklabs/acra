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

// Package filesystem implements keystores that write and reads keys from file system. Each keystore is responsible
// for generating keys for specific service, writing them to provided file path, reading and decrypting them.
// Server keystore generates AcraServer transport key pair and AcraStorage encryption keypair used for
// creating/decrypting AcraStructs.
// Connector keystore generates AcraConnector transport key pair.
// Translator keystore generates AcraTranslator transport key pair.
//
// https://github.com/cossacklabs/acra/wiki/Key-Management
package filesystem

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	fs "github.com/cossacklabs/acra/keystore/filesystem/internal"
	"github.com/cossacklabs/acra/keystore/lru"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// PrivateFileMode used for all created files with private data
const PrivateFileMode = os.FileMode(0600)

// publicFileMode used for all created files with public data
const publicFileMode = os.FileMode(0644)

const keyDirMode = os.FileMode(0700)

const (
	poisonPrivateKey   = "poison_key"
	poisonPublicKey    = "poison_key.pub"
	poisonSymmetricKey = "poison_key_sym"
	legacyWebConfigKey = "auth_key"
)

// ErrUnrecognizedKeyPurpose describe key mismatch error
var ErrUnrecognizedKeyPurpose = errors.New("key purpose not recognized")

// ErrInvalidIndex represent invalid key index for destroying
var ErrInvalidIndex = errors.New("invalid index value provided")

// KeyStore represents keystore that reads keys from key folders, and stores them in memory.
type KeyStore struct {
	cache               keystore.Cache
	privateKeyDirectory string
	publicKeyDirectory  string
	fs                  Storage
	lock                *sync.RWMutex
	encryptor           keystore.KeyEncryptor
	cacheEncryptor      keystore.KeyEncryptor
	encryptorCtx        context.Context
}

// NewFileSystemKeyStoreWithCacheSize represents keystore that reads keys from key folders, and stores them in cache.
func NewFileSystemKeyStoreWithCacheSize(directory string, encryptor keystore.KeyEncryptor, cacheSize int) (*KeyStore, error) {
	return NewCustomFilesystemKeyStore().KeyDirectory(directory).Encryptor(encryptor).CacheSize(cacheSize).Build()
}

// NewFilesystemKeyStore represents keystore that reads keys from key folders, and stores them in memory.
func NewFilesystemKeyStore(directory string, encryptor keystore.KeyEncryptor) (*KeyStore, error) {
	return NewCustomFilesystemKeyStore().KeyDirectory(directory).Encryptor(encryptor).Build()
}

// NewFilesystemKeyStoreTwoPath creates new KeyStore using separate folders for private and public keys.
func NewFilesystemKeyStoreTwoPath(privateKeyFolder, publicKeyFolder string, encryptor keystore.KeyEncryptor) (*KeyStore, error) {
	return NewCustomFilesystemKeyStore().KeyDirectories(privateKeyFolder, publicKeyFolder).Encryptor(encryptor).Build()
}

// KeyStoreBuilder allows to build a custom keystore.
type KeyStoreBuilder struct {
	privateKeyDir string
	publicKeyDir  string
	encryptor     keystore.KeyEncryptor
	storage       Storage
	cacheSize     int
}

// NewCustomFilesystemKeyStore allows a custom-made KeyStore to be built.
// You must set at least root key directories and provide a KeyEncryptor.
func NewCustomFilesystemKeyStore() *KeyStoreBuilder {
	return &KeyStoreBuilder{
		storage:   &DummyStorage{},
		cacheSize: keystore.InfiniteCacheSize,
	}
}

// KeyDirectory sets root key directory. Private and public keys will be kept together.
func (b *KeyStoreBuilder) KeyDirectory(directory string) *KeyStoreBuilder {
	b.privateKeyDir = directory
	b.publicKeyDir = directory
	return b
}

// KeyDirectories sets root key directories for private and public keys.
func (b *KeyStoreBuilder) KeyDirectories(privateKeyDir, publicKeyDir string) *KeyStoreBuilder {
	b.privateKeyDir = privateKeyDir
	b.publicKeyDir = publicKeyDir
	return b
}

// Encryptor sets cryptographic backend.
func (b *KeyStoreBuilder) Encryptor(encryptor keystore.KeyEncryptor) *KeyStoreBuilder {
	b.encryptor = encryptor
	return b
}

// Storage sets custom storage backend.
func (b *KeyStoreBuilder) Storage(storage Storage) *KeyStoreBuilder {
	b.storage = storage
	return b
}

// CacheSize sets cache size to use. By default cache size is unlimited,
func (b *KeyStoreBuilder) CacheSize(cacheSize int) *KeyStoreBuilder {
	b.cacheSize = cacheSize
	return b
}

var (
	errNoPrivateKeyDir = errors.New("private key directory not specified")
	errNoPublicKeyDir  = errors.New("public key directory not specified")
	errNoEncryptor     = errors.New("encryptor not specified")
)

// Build constructs a KeyStore with specified parameters.
func (b *KeyStoreBuilder) Build() (*KeyStore, error) {
	if b.privateKeyDir == "" {
		return nil, errNoPrivateKeyDir
	}
	if b.publicKeyDir == "" {
		return nil, errNoPublicKeyDir
	}
	if b.encryptor == nil {
		return nil, errNoEncryptor
	}
	return newFilesystemKeyStore(b.privateKeyDir, b.publicKeyDir, b.storage, b.encryptor, b.cacheSize)
}

// IsKeyDirectory checks if the local directory contains a keystore v1.
// This is a conservative check.
// That is, positive return value does not mean that the directory contains *a valid* keystore.
// However, false value means that the directory is definitely not a valid keystore.
// In particular, false is returned if the directory does not exists or cannot be opened.
func IsKeyDirectory(keyDirectory string, extractor *cmd.ServiceParamsExtractor) bool {
	storage, err := openKeyStorage(extractor)
	if err != nil {
		log.WithError(err).Debug("Failed to open key storage for version check")
		return false
	}
	fi, err := storage.Stat(keyDirectory)
	if err != nil {
		log.WithError(err).WithField("path", keyDirectory).Debug("Failed to stat key directory for version check")
		return false
	}
	if !fi.IsDir() {
		log.WithField("path", keyDirectory).Debug("Key directory is not a directory")
		return false
	}
	files, err := storage.ReadDir(keyDirectory)
	if err != nil {
		log.WithError(err).WithField("path", keyDirectory).Debug("Failed to read key directory for version check")
		return false
	}
	if len(files) == 0 {
		log.WithField("path", keyDirectory).Debug("Key directory is empty")
		return false
	}
	return true
}

func openKeyStorage(extractor *cmd.ServiceParamsExtractor) (Storage, error) {
	redis := cmd.ParseRedisCLIParametersFromFlags(extractor, "")
	if redis.KeysConfigured() {
		return NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
	}
	return &DummyStorage{}, nil
}

func newFilesystemKeyStore(privateKeyFolder, publicKeyFolder string, storage Storage, encryptor keystore.KeyEncryptor, cacheSize int) (*KeyStore, error) {
	fi, err := storage.Stat(privateKeyFolder)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if !os.IsNotExist(err) {
		const expectedPermission = "-rwx------"
		if runtime.GOOS == "linux" && fi.Mode().Perm().String() != expectedPermission {
			log.Errorf("Keystore folder has an incorrect permissions %s, expected: %s", fi.Mode().Perm().String(), expectedPermission)
			return nil, errors.New("keystore folder has an incorrect permissions")
		}
	}
	_, err = storage.Stat(publicKeyFolder)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var cache keystore.Cache
	var cacheEncryptor keystore.KeyEncryptor

	if cacheSize == keystore.WithoutCache {
		cacheEncryptor = dummyEncryptor{}
		cache = keystore.NoCache{}
	} else {
		cache, err = lru.NewCacheKeystoreWrapper(cacheSize)
		if err != nil {
			return nil, err
		}

		cacheEncryptionKey, err := keystore.GenerateSymmetricKey()
		if err != nil {
			log.WithError(err).Errorln("Can't generate cache encryption key")
			return nil, err
		}

		cacheEncryptor, err = keystore.NewSCellKeyEncryptor(cacheEncryptionKey)
		if err != nil {
			log.WithError(err).Errorln("Can't init cache scell encryptor")
			return nil, err
		}
	}

	ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)
	store := &KeyStore{privateKeyDirectory: privateKeyFolder, publicKeyDirectory: publicKeyFolder,
		cache: cache, lock: &sync.RWMutex{}, encryptor: encryptor, cacheEncryptor: cacheEncryptor, fs: storage, encryptorCtx: ctx}
	// set callback on cache value removing

	return store, nil
}

// CacheOnStart list and cache all keys from keystore
func (store *KeyStore) CacheOnStart() error {
	descriptions, err := store.ListKeys()
	if err != nil {
		return err
	}

	for _, desc := range descriptions {
		switch desc.Purpose {
		case keystore.PurposePoisonRecordSymmetricKey:
			if _, err = store.GetPoisonSymmetricKeys(); err != nil {
				return err
			}
		case keystore.PurposePoisonRecordKeyPair:
			if _, err = store.GetPoisonKeyPair(); err != nil {
				return err
			}
		case keystore.PurposeSearchHMAC:
			if _, err = store.GetHMACSecretKey([]byte(desc.ClientID)); err != nil {
				return err
			}
		case keystore.PurposeAuditLog:
			if _, err = store.GetLogSecretKey(); err != nil {
				return err
			}
		case keystore.PurposeStorageClientSymmetricKey:
			if _, err = store.GetClientIDSymmetricKeys([]byte(desc.ClientID)); err != nil {
				return err
			}
		case keystore.PurposeStorageClientPrivateKey:
			if _, err = store.GetServerDecryptionPrivateKey([]byte(desc.ClientID)); err != nil {
				return err
			}
		case keystore.PurposeStorageClientPublicKey:
			if _, err = store.GetClientIDEncryptionPublicKey([]byte(desc.ClientID)); err != nil {
				return err
			}
		default:
			return ErrUnrecognizedKeyPurpose
		}
	}
	return nil
}

func (store *KeyStore) generateKeyPair(filename string, keyContext keystore.KeyContext) (*keys.Keypair, error) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		return nil, err
	}
	if err := store.SaveKeyPairWithFilename(keypair, filename, keyContext); err != nil {
		return nil, err
	}
	return keypair, nil
}

// SaveKeyPairWithFilename save encrypted private key and public key to configured folders
func (store *KeyStore) SaveKeyPairWithFilename(keypair *keys.Keypair, filename string, keyContext keystore.KeyContext) error {
	privateKeysFolder := filepath.Dir(store.GetPrivateKeyFilePath(filename))
	err := store.fs.MkdirAll(privateKeysFolder, keyDirMode)
	if err != nil {
		return err
	}

	publicKeysFolder := filepath.Dir(store.GetPublicKeyFilePath(filename))
	err = store.fs.MkdirAll(publicKeysFolder, keyDirMode)
	if err != nil {
		return err
	}

	encryptedPrivate, err := store.encryptor.Encrypt(store.encryptorCtx, keypair.Private.Value, keyContext)
	if err != nil {
		return err
	}
	err = store.WritePrivateKey(store.GetPrivateKeyFilePath(filename), encryptedPrivate)
	if err != nil {
		return err
	}
	err = store.WritePublicKey(store.GetPublicKeyFilePath(filename+".pub"), keypair.Public.Value)
	if err != nil {
		return err
	}

	cacheEncryptedPrivate, err := store.cacheEncryptor.Encrypt(store.encryptorCtx, keypair.Private.Value, keyContext)
	if err != nil {
		return err
	}
	store.cache.Add(filename, cacheEncryptedPrivate)
	store.cache.Add(filename+".pub", keypair.Public.Value)
	return nil
}

func (store *KeyStore) generateKey(filename string, length uint8) ([]byte, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		log.Error(err)
		return nil, err
	}
	dirpath := filepath.Dir(store.GetPrivateKeyFilePath(filename))
	err = store.fs.MkdirAll(dirpath, keyDirMode)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	err = store.WritePrivateKey(store.GetPrivateKeyFilePath(filename), randomBytes)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return randomBytes, nil
}

// WritePrivateKey writes private key from data to filename
func (store *KeyStore) WritePrivateKey(filename string, data []byte) error {
	return store.WriteKeyFile(filename, data, PrivateFileMode)
}

// WritePublicKey writes public key from data to filename
func (store *KeyStore) WritePublicKey(filename string, data []byte) error {
	return store.WriteKeyFile(filename, data, publicFileMode)
}

// ReadKeyFile reads raw key data for given filename.
func (store *KeyStore) ReadKeyFile(filename string) ([]byte, error) {
	return store.fs.ReadFile(filename)
}

// WriteKeyFile updates key data, creating a new file if necessary.
func (store *KeyStore) WriteKeyFile(filename string, data []byte, mode os.FileMode) error {
	if err := store.fs.MkdirAll(filepath.Dir(filename), keyDirMode); err != nil {
		return err
	}

	// We do quite a few filesystem manipulations to maintain old key data. Ensure that
	// no data is lost due to errors or power faults. "filename" must contain either
	// new key data on success, or old key data on error.
	tmpFilename, err := store.fs.TempFile(filename, mode)
	if err != nil {
		return err
	}
	err = store.fs.WriteFile(tmpFilename, data, mode)
	if err != nil {
		return err
	}
	err = store.backupHistoricalKeyFile(filename)
	if err != nil {
		return err
	}
	err = store.fs.Rename(tmpFilename, filename)
	if err != nil {
		return err
	}
	return nil
}

func (store *KeyStore) backupHistoricalKeyFile(filename string) error {
	// If the file does not exist then there's nothing to backup
	_, err := store.fs.Stat(filename)
	if os.IsNotExist(err) {
		return nil
	}
	err = store.fs.MkdirAll(getHistoryDirName(filename), keyDirMode)
	if err != nil {
		return err
	}
	backupName := getNewHistoricalFileName(filename)
	// Try making a hard link if possible to avoid actually copying file content
	err = store.fs.Link(filename, backupName)
	if err == nil {
		return nil
	}
	return store.fs.Copy(filename, backupName)
}

// GetPrivateKeyFilePath return path for file with private key with configured folder for store
func (store *KeyStore) GetPrivateKeyFilePath(filename string) string {
	return fmt.Sprintf("%s%s%s", store.privateKeyDirectory, string(os.PathSeparator), filename)
}

// GetPublicKeyFilePath return path for file with public key with configured folder for store
func (store *KeyStore) GetPublicKeyFilePath(filename string) string {
	return fmt.Sprintf("%s%s%s", store.publicKeyDirectory, string(os.PathSeparator), filename)
}

// use key started with "." (dot) because it's invalid character for clientID that generally stored in cache and
// it will not intersect with other keys
const cacheKeyPrefix = ".historical."

var errCacheMissHistoricalFilenames = errors.New("cache doesn't contain historical filenames")

func (store *KeyStore) getCachedHistoricalPrivateKeyFilenames(id string) ([]string, error) {
	key := cacheKeyPrefix + id
	value, ok := store.cache.Get(key)
	if !ok {
		return nil, errCacheMissHistoricalFilenames
	}
	paths := &fs.HistoricalPaths{}
	_, err := paths.UnmarshalMsg(value)
	if err != nil {
		return nil, err
	}
	return paths.Paths, nil
}

func (store *KeyStore) cacheHistoricalPrivateKeyFilenames(id string, paths []string) error {
	values := &fs.HistoricalPaths{Paths: paths}
	serialized, err := values.MarshalMsg(nil)
	if err != nil {
		return err
	}
	key := cacheKeyPrefix + id
	store.cache.Add(key, serialized)
	return nil
}

// GetHistoricalPrivateKeyFilenames return filenames for current and rotated keys
func (store *KeyStore) GetHistoricalPrivateKeyFilenames(filename string) ([]string, error) {
	// getHistoricalFilePaths() expects a path, not a name, but we must return names.
	// Add private key directory path and then remove it to avoid directory switching.
	fullPath := filepath.Join(store.privateKeyDirectory, filename)
	paths, err := store.getCachedHistoricalPrivateKeyFilenames(fullPath)
	if err == nil {
		return paths, nil
	}
	// check that error is not expected errCacheMissHistoricalFilenames
	if err != nil && err != errCacheMissHistoricalFilenames {
		// log but don't return error to continue processing. less performance, more stability
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCacheIssues).
			WithError(err).
			Errorln("Can't get cache value of historical private key filenames")
	}

	paths, err = getHistoricalFilePaths(fullPath, store.fs)
	if err != nil {
		return nil, err
	}
	for i, path := range paths {
		p, err := filepath.Rel(store.privateKeyDirectory, path)
		if err != nil {
			return nil, err
		}
		paths[i] = p
	}
	if err := store.cacheHistoricalPrivateKeyFilenames(fullPath, paths); err != nil {
		// log but don't return error to continue processing. less performance, more stability
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCacheIssues).
			WithError(err).
			Errorln("Can't cache historical private key filenames")
	}
	return paths, nil
}

func (store *KeyStore) loadPrivateKey(path string) (*keys.PrivateKey, error) {
	fi, err := store.fs.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "linux" && fi.Mode().Perm() > PrivateFileMode {
		log.Errorf("Private key file %v has incorrect permissions %s, expected: %s", path, fi.Mode().Perm().String(), PrivateFileMode.String())
		return nil, fmt.Errorf("private key file %v has incorrect permissions", path)
	}
	// Strictly speaking, this is racy because the file we were statting
	// may not be the same as we will be reading, but it's okay in this case.
	key, err := store.fs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: key}, nil
}

func (store *KeyStore) loadPublicKey(path string) (*keys.PublicKey, error) {
	key, err := store.fs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: key}, nil
}

func (store *KeyStore) getPrivateKeyByFilename(filename string, keyContext keystore.KeyContext) (*keys.PrivateKey, error) {
	store.lock.Lock()
	defer store.lock.Unlock()
	encryptedKey, ok := store.cache.Get(filename)
	if !ok {
		loadKeyCallback := func() ([]byte, error) {
			encryptedPrivateKey, err := store.loadPrivateKey(store.GetPrivateKeyFilePath(filename))
			if err != nil {
				return nil, err
			}
			return encryptedPrivateKey.Value, nil
		}

		loadedKey, err := store.loadKeyAndCache(filename, keyContext, loadKeyCallback)
		if err != nil {
			return nil, err
		}
		return &keys.PrivateKey{Value: loadedKey}, nil
	}

	decryptedKey, err := store.cacheEncryptor.Decrypt(store.encryptorCtx, encryptedKey, keyContext)
	if err != nil {
		return nil, err
	}

	return &keys.PrivateKey{Value: decryptedKey}, nil
}

func (store *KeyStore) getPrivateKeysByFilenames(filenames []string, keyContext keystore.KeyContext) ([]*keys.PrivateKey, error) {
	// TODO: this can be optimized to avoid thrashing store.lock and repeatedly revalidating id
	// by copy-pasting getPrivateKeyByFilename() and extending that to retrieve multiple keys
	privateKeys := make([]*keys.PrivateKey, len(filenames))
	for i, name := range filenames {
		key, err := store.getPrivateKeyByFilename(name, keyContext)
		if err != nil {
			utils.ZeroizePrivateKeys(privateKeys)
			return nil, err
		}
		privateKeys[i] = key
	}
	return privateKeys, nil
}

// getPublicKeyByFilename return public key from cache or load from filesystem, store in cache and return
func (store *KeyStore) getPublicKeyByFilename(filename string) (*keys.PublicKey, error) {
	binKey, ok := store.cache.Get(filename)
	if !ok {
		publicKey, err := store.loadPublicKey(filename)
		if err != nil {
			return nil, err
		}
		store.cache.Add(filename, publicKey.Value)
		return publicKey, nil
	}
	return &keys.PublicKey{Value: binKey}, nil
}

// GetClientIDEncryptionPublicKey return PublicKey by clientID from cache or load from main store
func (store *KeyStore) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	fname := store.GetPublicKeyFilePath(
		// use correct suffix for public keys
		getPublicKeyFilename(
			// use correct suffix as type of key
			[]byte(GetServerDecryptionKeyFilename(clientID))))
	return store.getPublicKeyByFilename(fname)
}

// GetPeerPublicKey returns public key for this clientID, gets it from cache or reads from fs.
func (store *KeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	if !keystore.ValidateID(id) {
		return nil, keystore.ErrInvalidClientID
	}
	fname := getPublicKeyFilename(id)
	store.lock.Lock()
	defer store.lock.Unlock()
	key, ok := store.cache.Get(fname)
	if ok {
		log.Debugf("Load cached key: %s", fname)
		return &keys.PublicKey{Value: key}, nil
	}
	publicKey, err := store.loadPublicKey(store.GetPublicKeyFilePath(fname))
	if err != nil {
		return nil, err
	}
	log.Debugf("Load key from fs: %s", fname)
	store.cache.Add(fname, publicKey.Value)
	return publicKey, nil
}

// GetPrivateKey reads encrypted client private key from fs, decrypts it with master key and clientID,
// and returns plaintext private key, or reading/decryption error.
func (store *KeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := getServerKeyFilename(id)

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, id)
	return store.getPrivateKeyByFilename(fname, keyContext)
}

// GetServerDecryptionPrivateKey reads encrypted server storage private key from fs,
// decrypts it with master key and clientID,
// and returns plaintext private key, or reading/decryption error.
func (store *KeyStore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	fname := GetServerDecryptionKeyFilename(id)
	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, id)
	return store.getPrivateKeyByFilename(fname, keyContext)
}

// GetServerDecryptionPrivateKeys reads encrypted server storage private keys from fs,
// decrypts them with master key and clientID, and returns plaintext private keys,
// or reading/decryption error.
func (store *KeyStore) GetServerDecryptionPrivateKeys(id []byte) ([]*keys.PrivateKey, error) {
	filenames, err := store.GetHistoricalPrivateKeyFilenames(GetServerDecryptionKeyFilename(id))
	if err != nil {
		return nil, err
	}

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, id)
	return store.getPrivateKeysByFilenames(filenames, keyContext)
}

// GenerateConnectorKeys generates AcraConnector transport EC keypair using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateConnectorKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}
	filename := getConnectorKeyFilename(id)

	keyContext := keystore.NewKeyContext(keystore.PurposeLegacy, id)
	_, err := store.generateKeyPair(filename, keyContext)
	if err != nil {
		return err
	}
	return nil
}

// GenerateServerKeys generates AcraServer transport EC keypair using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateServerKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}
	filename := getServerKeyFilename(id)

	keyContext := keystore.NewKeyContext(keystore.PurposeLegacy, id)
	_, err := store.generateKeyPair(filename, keyContext)
	if err != nil {
		return err
	}
	return nil
}

// GenerateTranslatorKeys generates AcraTranslator transport EC keypair using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateTranslatorKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}
	filename := getTranslatorKeyFilename(id)

	keyContext := keystore.NewKeyContext(keystore.PurposeLegacy, id)
	_, err := store.generateKeyPair(filename, keyContext)
	if err != nil {
		return err
	}
	return nil
}

// GenerateDataEncryptionKeys generates Storage EC keypair for encrypting/decrypting data
// using clientID as part of key name.
// Writes encrypted private key and plaintext public key to fs.
// Returns error if writing/encryption failed.
func (store *KeyStore) GenerateDataEncryptionKeys(id []byte) error {
	if !keystore.ValidateID(id) {
		return keystore.ErrInvalidClientID
	}

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, id)
	_, err := store.generateKeyPair(GetServerDecryptionKeyFilename(id), keyContext)
	if err != nil {
		return err
	}
	return nil
}

// ListKeys enumerates keys present in the keystore.
func (store *KeyStore) ListKeys() ([]keystore.KeyDescription, error) {
	keys, err := store.describeDir(store.privateKeyDirectory)
	if err != nil {
		return nil, err
	}

	if store.publicKeyDirectory != store.privateKeyDirectory {
		publicKeys, err := store.describeDir(store.publicKeyDirectory)
		if err != nil {
			return nil, err
		}
		keys = append(keys, publicKeys...)
	}

	return keys, nil
}

// ListRotatedKeys enumerates keys present in the keystore within old dir.
func (store *KeyStore) ListRotatedKeys() ([]keystore.KeyDescription, error) {
	keys, err := store.describeOldDir(store.privateKeyDirectory)
	if err != nil {
		return nil, err
	}

	if store.publicKeyDirectory != store.privateKeyDirectory {
		publicKeys, err := store.describeOldDir(store.publicKeyDirectory)
		if err != nil {
			return nil, err
		}
		keys = append(keys, publicKeys...)
	}

	return keys, nil
}

func (store *KeyStore) describeDir(dirName string) ([]keystore.KeyDescription, error) {
	files, err := store.fs.ReadDir(dirName)
	if err != nil {
		return nil, err
	}

	keys := make([]keystore.KeyDescription, 0, len(files))
	for _, fileInfo := range files {
		if fileInfo.IsDir() && fileInfo.Name() == ".poison_key" {
			//recursive read to scan poison directory
			poisonKeys, err := store.describeDir(filepath.Join(dirName, fileInfo.Name()))
			if err != nil {
				return nil, err
			}
			keys = append(keys, poisonKeys...)

			continue
		}

		if strings.HasSuffix(fileInfo.Name(), "old") {
			continue
		}

		description, err := DescribeKeyFile(fileInfo.Name())
		if err != nil {
			return nil, err
		}
		if description.Purpose == keystore.PurposeLegacy {
			log.WithField("KeyID", description.KeyID).Warn("Ignoring legacy key")
			continue
		}

		// virtual index of current key always 1
		description.Index = 1
		description.State = keystore.StateCurrent
		keys = append(keys, *description)
	}
	return keys, nil
}

func (store *KeyStore) describeOldDir(dirName string) ([]keystore.KeyDescription, error) {
	files, err := store.fs.ReadDir(dirName)
	if err != nil {
		return nil, err
	}

	keys := make([]keystore.KeyDescription, 0, len(files))
	for _, fileInfo := range files {
		if fileInfo.IsDir() && fileInfo.Name() == ".poison_key" {
			//recursive read to scan poison directory
			poisonKeys, err := store.describeOldDir(filepath.Join(dirName, fileInfo.Name()))
			if err != nil {
				return nil, err
			}
			keys = append(keys, poisonKeys...)

			continue
		}

		if !fileInfo.IsDir() || !strings.HasSuffix(fileInfo.Name(), "old") {
			continue
		}

		// remove old suffix from dir name and path it to get KeyDescription
		fileName := strings.TrimSuffix(fileInfo.Name(), ".old")

		description, err := DescribeKeyFile(fileName)
		if err != nil {
			return nil, err
		}
		if description.Purpose == keystore.PurposeLegacy {
			log.WithField("KeyID", description.KeyID).Warn("Ignoring legacy key")
			continue
		}

		// read files inside directory with old prefix
		files, err = store.fs.ReadDir(filepath.Join(dirName, fileInfo.Name()))
		if err != nil {
			return nil, err
		}

		if len(files) == 0 {
			log.WithField("KeyID", fileInfo.Name()).Warn("Contains no key files")
			continue
		}

		// 1 is always index of current key of the keystore
		// all rotated keys have index after 1
		var rotatedKeyIdx = 2
		for _, file := range files {
			if file.IsDir() {
				log.WithField("KeyID", file.Name()).Warn("Expected no directories in rotated keys folder")
				return nil, errors.New("expected no directories in rotated keys folder")
			}

			creationTime, err := time.Parse(HistoricalFileNameTimeFormat, file.Name())
			if err != nil {
				return nil, err
			}

			descriptionWithTime := keystore.KeyDescription{
				Index:        rotatedKeyIdx,
				KeyID:        description.KeyID,
				Purpose:      description.Purpose,
				ClientID:     description.ClientID,
				CreationTime: &creationTime,
				State:        keystore.StateRotated,
			}

			keys = append(keys, descriptionWithTime)
			rotatedKeyIdx++
		}
	}
	return keys, nil
}

// Reset clears all cached keys
func (store *KeyStore) Reset() {
	store.cache.Clear()
}

// GetPoisonKeyPair reads and returns poison EC keypair from the fs.
// Returns an error if fs or crypto operations fail. Also, returns ErrKeysNotFound
// if the key pair doesn't exist.
func (store *KeyStore) GetPoisonKeyPair() (*keys.Keypair, error) {
	keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordKeyPair, []byte(PoisonKeyFilename))

	privateKey, privateOk := store.cache.Get(PoisonKeyFilename)
	publicKey, publicOk := store.cache.Get(poisonKeyFilenamePublic)
	if privateOk && publicOk {
		decryptedPrivate, err := store.cacheEncryptor.Decrypt(store.encryptorCtx, privateKey, keyContext)
		if err != nil {
			return nil, err
		}
		return &keys.Keypair{Public: &keys.PublicKey{Value: publicKey}, Private: &keys.PrivateKey{Value: decryptedPrivate}}, nil
	}
	privatePath := store.GetPrivateKeyFilePath(PoisonKeyFilename)
	private, err := store.loadPrivateKey(privatePath)
	if err != nil {
		if IsKeyReadError(err) {
			return nil, keystore.ErrKeysNotFound
		}
		return nil, err
	}
	if private.Value, err = store.encryptor.Decrypt(store.encryptorCtx, private.Value, keyContext); err != nil {
		return nil, err
	}

	cacheEncrypted, err := store.cacheEncryptor.Encrypt(store.encryptorCtx, private.Value, keyContext)
	if err != nil {
		return nil, err
	}

	publicPath := store.GetPublicKeyFilePath(poisonKeyFilenamePublic)
	public, err := store.loadPublicKey(publicPath)
	if err != nil {
		return nil, err
	}

	store.cache.Add(PoisonKeyFilename, cacheEncrypted)
	store.cache.Add(poisonKeyFilenamePublic, public.Value)
	return &keys.Keypair{Public: public, Private: private}, nil
}

// GetPoisonPrivateKeys reads and returns poison EC private keys from the fs,
// returning them in order from newest to oldest.
// Returns an error if fs or crypto operations fail. Also, returns
// ErrKeysNotFound if the keys don't exist.
func (store *KeyStore) GetPoisonPrivateKeys() ([]*keys.PrivateKey, error) {
	// If some poison keypairs exist, pull their private keys.
	filenames, err := store.GetHistoricalPrivateKeyFilenames(PoisonKeyFilename)
	if err != nil {
		return nil, err
	}

	keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordKeyPair, []byte(PoisonKeyFilename))
	poisonKeys, err := store.getPrivateKeysByFilenames(filenames, keyContext)
	if err != nil {
		if IsKeyReadError(err) {
			return nil, keystore.ErrKeysNotFound
		}
		return nil, err
	}
	if len(poisonKeys) == 0 {
		return nil, keystore.ErrKeysNotFound
	}
	return poisonKeys, nil
}

// GetPoisonSymmetricKeys reads and returns all poison symmetric keys from the
// fs, returning them in order from newest to oldest.
// Returns an error if fs or crypto operations fail. Also, returns
// ErrKeysNotFound if the keys don't exist.
func (store *KeyStore) GetPoisonSymmetricKeys() ([][]byte, error) {
	keyFileName := getSymmetricKeyName(PoisonKeyFilename)

	keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordSymmetricKey, []byte(keyFileName))
	keys, err := store.getSymmetricKeys(keyFileName, keyContext)

	if err != nil {
		if IsKeyReadError(err) {
			return nil, keystore.ErrKeysNotFound
		}
		return nil, err
	}
	if len(keys) == 0 {
		return nil, keystore.ErrKeysNotFound
	}
	return keys, nil
}

// GetPoisonSymmetricKey reads and returns poison symmetric key from the fs.
// Returns an error if fs or crypto operations fail. Also, returns
// ErrKeysNotFound if the keys don't exist.
func (store *KeyStore) GetPoisonSymmetricKey() ([]byte, error) {
	keyFileName := getSymmetricKeyName(PoisonKeyFilename)

	keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordSymmetricKey, []byte(keyFileName))
	key, err := store.getLatestSymmetricKey(keyFileName, keyContext)
	if err == nil {
		return key, nil
	}

	if IsKeyReadError(err) {
		return nil, keystore.ErrKeysNotFound
	}

	return nil, err
}

// SaveDataEncryptionKeys save or overwrite decryption keypair for client id
func (store *KeyStore) SaveDataEncryptionKeys(id []byte, keypair *keys.Keypair) error {
	filename := GetServerDecryptionKeyFilename(id)

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientPrivateKey, id)
	return store.SaveKeyPairWithFilename(keypair, filename, keyContext)
}

// destroyKeyWithFilename removes private and public key with given filename.
func (store *KeyStore) destroyKeyWithFilename(filename string) error {
	// Purge private key data from cache too.
	store.cache.Add(filename, nil)
	store.cache.Add(filename+".pub", nil)

	// Remove key files. It's okay if they are already removed (or never existed).
	// Keystore v1 does not differentiate between 'destroying' and 'removing' keys
	// because multiple functinons depend on the key file to be absent, not empty.
	err := store.fs.Remove(store.GetPrivateKeyFilePath(filename))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	err = store.fs.Remove(store.GetPublicKeyFilePath(filename + ".pub"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// destroySymmetricKeyWithFilename removes symmetric key with given filename.
func (store *KeyStore) destroySymmetricKeyWithFilename(filename string) error {
	// Purge key data from cache too.
	store.cache.Add(filename, nil)

	// Remove key files. It's okay if they are already removed (or never existed).
	// Keystore v1 does not differentiate between 'destroying' and 'removing' keys
	// because multiple functinons depend on the key file to be absent, not empty.
	err := store.fs.Remove(store.GetPrivateKeyFilePath(getSymmetricKeyName(filename)))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// Add value to inner cache
func (store *KeyStore) Add(keyID string, keyValue []byte) {
	store.cache.Add(keyID, keyValue)
}

// Get value from inner cache
func (store *KeyStore) Get(keyID string) ([]byte, bool) {
	return store.cache.Get(keyID)
}

// GetHMACSecretKey return key for hmac calculation according to id
func (store *KeyStore) GetHMACSecretKey(id []byte) ([]byte, error) {
	filename := getHmacKeyFilename(id)
	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeSearchHMAC, id)

	encryptedKey, ok := store.Get(filename)
	if !ok {
		return store.loadKeyAndCache(filename, keyContext, func() ([]byte, error) {
			return store.ReadKeyFile(store.GetPrivateKeyFilePath(filename))
		})
	}
	return store.cacheEncryptor.Decrypt(store.encryptorCtx, encryptedKey, keyContext)
}

// GenerateHmacKey key for hmac calculation in in folder for private keys
func (store *KeyStore) GenerateHmacKey(id []byte) error {
	log.Debugln("Generate HMAC")
	key, err := keystore.GenerateSymmetricKey()
	if err != nil {
		return err
	}

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeSearchHMAC, id)
	encryptedKey, err := store.encryptor.Encrypt(store.encryptorCtx, key, keyContext)
	if err != nil {
		return err
	}

	cacheEncryptedKey, err := store.cacheEncryptor.Encrypt(store.encryptorCtx, key, keyContext)
	if err != nil {
		return err
	}

	utils.ZeroizeSymmetricKey(key)

	path := store.GetPrivateKeyFilePath(getHmacKeyFilename(id))
	err = store.WriteKeyFile(path, encryptedKey, PrivateFileMode)
	if err != nil {
		return err
	}

	store.Add(getHmacKeyFilename(id), cacheEncryptedKey)

	return nil
}

// GenerateLogKey key for log integrity check calculation in folder for private keys
func (store *KeyStore) GenerateLogKey() error {
	log.Debugln("Generate secure log key")
	key, err := keystore.GenerateSymmetricKey()
	if err != nil {
		return err
	}

	keyContext := keystore.NewKeyContext(keystore.PurposeAuditLog, []byte(SecureLogKeyFilename))
	encryptedKey, err := store.encryptor.Encrypt(store.encryptorCtx, key, keyContext)
	if err != nil {
		return err
	}

	cacheEncryptedKey, err := store.cacheEncryptor.Encrypt(store.encryptorCtx, key, keyContext)
	if err != nil {
		return err
	}

	utils.ZeroizeSymmetricKey(key)

	path := store.GetPrivateKeyFilePath(getLogKeyFilename())
	err = store.WriteKeyFile(path, encryptedKey, PrivateFileMode)
	if err != nil {
		return err
	}

	store.Add(getLogKeyFilename(), cacheEncryptedKey)

	return nil
}

// GetLogSecretKey return key for log integrity checks
func (store *KeyStore) GetLogSecretKey() ([]byte, error) {
	filename := getLogKeyFilename()
	keyContext := keystore.NewKeyContext(keystore.PurposeAuditLog, []byte(SecureLogKeyFilename))

	encryptedKey, ok := store.Get(filename)
	if !ok {
		return store.loadKeyAndCache(filename, keyContext, func() ([]byte, error) {
			return store.ReadKeyFile(store.GetPrivateKeyFilePath(filename))
		})
	}

	return store.cacheEncryptor.Decrypt(store.encryptorCtx, encryptedKey, keyContext)
}

// generateSymmetricKey generate symmetric key with specific identifier
func (store *KeyStore) generateAndSaveSymmetricKey(filename string, keyContext keystore.KeyContext) error {
	symKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		return err
	}

	encryptedSymKey, err := store.encryptor.Encrypt(store.encryptorCtx, symKey, keyContext)
	if err != nil {
		return err
	}
	return store.WritePrivateKey(filename, encryptedSymKey)
}

// GetSymmetricKey return symmetric key with specific identifier
func (store *KeyStore) readEncryptedKey(filename string, keyContext keystore.KeyContext) ([]byte, error) {
	encryptedSymKey, ok := store.Get(filename)
	if !ok {
		return store.loadKeyAndCache(filename, keyContext, func() ([]byte, error) {
			return store.ReadKeyFile(store.GetPrivateKeyFilePath(filename))
		})
	}
	return store.cacheEncryptor.Decrypt(store.encryptorCtx, encryptedSymKey, keyContext)
}

func (store *KeyStore) loadKeyAndCache(filename string, keyContext keystore.KeyContext, loadKeyCallback func() ([]byte, error)) ([]byte, error) {
	encryptedKey, err := loadKeyCallback()
	if err != nil {
		return nil, err
	}
	decrypted, err := store.encryptor.Decrypt(store.encryptorCtx, encryptedKey, keyContext)
	if err != nil {
		return nil, err
	}

	cacheEncrypted, err := store.cacheEncryptor.Encrypt(store.encryptorCtx, decrypted, keyContext)
	if err != nil {
		log.WithError(err).WithField("id", keyContext.Context).Debugln("Failed to encrypt with cacheEncryptor")
		return nil, err
	}

	log.Debugf("Load key from fs: %s", filename)
	store.Add(filename, cacheEncrypted)
	return decrypted, nil
}

// GenerateClientIDSymmetricKey generate symmetric key for specified client id
func (store *KeyStore) GenerateClientIDSymmetricKey(id []byte) error {
	keyName := getClientIDSymmetricKeyName(id)

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientSymmetricKey, id)
	return store.generateAndSaveSymmetricKey(store.GetPrivateKeyFilePath(keyName), keyContext)
}

// GeneratePoisonSymmetricKey generate symmetric key for poison records
func (store *KeyStore) GeneratePoisonSymmetricKey() error {
	keyName := getSymmetricKeyName(PoisonKeyFilename)
	keyPath := store.GetPrivateKeyFilePath(keyName)

	keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordSymmetricKey, []byte(keyName))
	return store.generateAndSaveSymmetricKey(keyPath, keyContext)
}

// GeneratePoisonKeyPair generates new poison keypair, saving it in the storage.
// Old keypair is rotated.
func (store *KeyStore) GeneratePoisonKeyPair() error {
	keyContext := keystore.NewKeyContext(keystore.PurposePoisonRecordKeyPair, []byte(PoisonKeyFilename))
	_, err := store.generateKeyPair(PoisonKeyFilename, keyContext)
	return err
}

func (store *KeyStore) getSymmetricKeys(keyname string, keyContext keystore.KeyContext) ([][]byte, error) {
	keys := make([][]byte, 0, 4)
	historicalKeys, err := store.GetHistoricalPrivateKeyFilenames(keyname)
	if err != nil {
		log.Debug("Can't get historical private key filenames")
		for _, key := range keys {
			utils.ZeroizeSymmetricKey(key)
		}
		return nil, err
	}
	for _, path := range historicalKeys {
		key, err := store.readEncryptedKey(path, keyContext)
		if err != nil {
			for _, key := range keys {
				utils.ZeroizeSymmetricKey(key)
			}
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (store *KeyStore) getLatestSymmetricKey(keyname string, keyContext keystore.KeyContext) ([]byte, error) {
	key, err := store.readEncryptedKey(keyname, keyContext)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GetClientIDSymmetricKeys return symmetric keys for specified client id
func (store *KeyStore) GetClientIDSymmetricKeys(id []byte) ([][]byte, error) {
	keyName := getClientIDSymmetricKeyName(id)

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientSymmetricKey, id)
	return store.getSymmetricKeys(keyName, keyContext)
}

// GetClientIDSymmetricKey return latest symmetric key for encryption by specified client id
func (store *KeyStore) GetClientIDSymmetricKey(id []byte) ([]byte, error) {
	keyName := getClientIDSymmetricKeyName(id)

	keyContext := keystore.NewClientIDKeyContext(keystore.PurposeStorageClientSymmetricKey, id)
	return store.getLatestSymmetricKey(keyName, keyContext)
}

// DestroyPoisonKeyPair destroy poison key pair
func (store *KeyStore) DestroyPoisonKeyPair() error {
	return store.destroyKeyWithFilename(PoisonKeyFilename)
}

// DestroyPoisonSymmetricKey destroy poison symmetric key
func (store *KeyStore) DestroyPoisonSymmetricKey() error {
	return store.destroySymmetricKeyWithFilename(PoisonKeyFilename)
}

// DestroyClientIDEncryptionKeyPair destroy server encryption key pair
func (store *KeyStore) DestroyClientIDEncryptionKeyPair(clientID []byte) error {
	return store.destroyKeyWithFilename(GetServerDecryptionKeyFilename(clientID))
}

// DestroyClientIDSymmetricKey destroy private poison key
func (store *KeyStore) DestroyClientIDSymmetricKey(clientID []byte) error {
	return store.destroySymmetricKeyWithFilename(GetServerDecryptionKeyFilename(clientID))
}

// DestroyHmacSecretKey destroy hmac secter key
func (store *KeyStore) DestroyHmacSecretKey(clientID []byte) error {
	return store.destroyKeyWithFilename(getHmacKeyFilename(clientID))
}

// DestroyRotatedPoisonKeyPair destroy poison rotated key pair by index
func (store *KeyStore) DestroyRotatedPoisonKeyPair(index int) error {
	if err := store.destroyRotatedKeyByIndex(store.GetPrivateKeyFilePath(PoisonKeyFilename), index); err != nil {
		return err
	}

	return store.destroyRotatedKeyByIndex(store.GetPublicKeyFilePath(poisonKeyFilenamePublic), index)
}

// DestroyRotatedPoisonSymmetricKey destroy created rotated poison record symmetric key
func (store *KeyStore) DestroyRotatedPoisonSymmetricKey(index int) error {
	keyName := getSymmetricKeyName(PoisonKeyFilename)
	return store.destroyRotatedKeyByIndex(store.GetPrivateKeyFilePath(keyName), index)
}

// DestroyRotatedClientIDEncryptionKeyPair destroy created rotated storage key pair
func (store *KeyStore) DestroyRotatedClientIDEncryptionKeyPair(clientID []byte, index int) error {
	fileName := GetServerDecryptionKeyFilename(clientID)

	if err := store.destroyRotatedKeyByIndex(store.GetPrivateKeyFilePath(fileName), index); err != nil {
		return err
	}

	pubKeyName := getPublicKeyFilename([]byte(fileName))
	return store.destroyRotatedKeyByIndex(store.GetPublicKeyFilePath(pubKeyName), index)
}

// DestroyRotatedClientIDSymmetricKey destroy created rotated symmetric key
func (store *KeyStore) DestroyRotatedClientIDSymmetricKey(clientID []byte, index int) error {
	keyName := getClientIDSymmetricKeyName(clientID)
	return store.destroyRotatedKeyByIndex(store.GetPrivateKeyFilePath(keyName), index)
}

// DestroyRotatedHmacSecretKey destroy created rotated hmac symmetric key
func (store *KeyStore) DestroyRotatedHmacSecretKey(clientID []byte, index int) error {
	keyName := getHmacKeyFilename(clientID)
	return store.destroyRotatedKeyByIndex(store.GetPrivateKeyFilePath(keyName), index)
}

func (store *KeyStore) destroyRotatedKeyByIndex(path string, index int) error {
	oldDir := getHistoryDirName(path)
	rotatedKeyFiles, err := store.fs.ReadDir(oldDir)
	if err != nil {
		return err
	}

	// 1 is always index of current key of the keystore
	// all rotated keys have index after 1
	if len(rotatedKeyFiles) == 0 || index > len(rotatedKeyFiles)+1 {
		return ErrInvalidIndex
	}

	rotatedKey := rotatedKeyFiles[index-1]
	err = store.fs.Remove(filepath.Join(oldDir, rotatedKey.Name()))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// DescribeKeyFile describes key by its purpose path for V1 and V2 keystore
func DescribeKeyFile(fileName string) (*keystore.KeyDescription, error) {
	description, ok, err := describeV2(fileName)
	if err != nil {
		return nil, err
	}

	if ok {
		return description, nil
	}

	description, ok, err = describeV1(fileName)
	if err != nil {
		return nil, err
	}

	if ok {
		return description, nil
	}

	return nil, ErrUnrecognizedKeyPurpose
}

// describe keys for V2 keystore
func describeV2(fileName string) (*keystore.KeyDescription, bool, error) {
	if !strings.HasSuffix(fileName, ".keyring") {
		return nil, false, nil
	}

	dir, file := path.Split(path.Clean(fileName))
	// dir was provided in path
	if dir != "" && strings.Contains(dir, "client") {
		splits := strings.Split(strings.Trim(dir, string(filepath.Separator)), string(filepath.Separator))
		if len(splits) == 1 {
			return nil, false, errors.New("invalid path provided for V2 keystore key")
		}

		switch strings.TrimSuffix(file, ".keyring") {
		case "hmac-sym":
			return &keystore.KeyDescription{
				KeyID:    file,
				ClientID: splits[len(splits)-1],
				Purpose:  keystore.PurposeSearchHMAC,
				State:    keystore.StateCurrent,
			}, true, nil
		case "storage":
			return &keystore.KeyDescription{
				KeyID:    file,
				ClientID: splits[len(splits)-1],
				Purpose:  keystore.PurposeStorageClientKeyPair,
				State:    keystore.StateCurrent,
			}, true, nil
		case "storage-sym":
			return &keystore.KeyDescription{
				KeyID:    file,
				ClientID: splits[len(splits)-1],
				Purpose:  keystore.PurposeStorageClientSymmetricKey,
				State:    keystore.StateCurrent,
			}, true, nil
		default:
			return nil, false, ErrUnrecognizedKeyPurpose
		}
	}

	switch strings.TrimSuffix(file, ".keyring") {
	case "audit-log":
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposeAuditLog,
			State:   keystore.StateCurrent,
		}, true, nil
	case "poison-record":
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposePoisonRecordKeyPair,
			State:   keystore.StateCurrent,
		}, true, nil
	case "poison-record-sym":
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposePoisonRecordSymmetricKey,
			State:   keystore.StateCurrent,
		}, true, nil
	default:
		return nil, false, ErrUnrecognizedKeyPurpose
	}
}

func describeV1(fileName string) (*keystore.KeyDescription, bool, error) {
	switch fileName {
	case poisonPrivateKey:
		return &keystore.KeyDescription{
			KeyID:   poisonPrivateKey,
			Purpose: keystore.PurposePoisonRecordKeyPair,
			State:   keystore.StateCurrent,
		}, true, nil
	case poisonPublicKey:
		return &keystore.KeyDescription{
			KeyID:   poisonPublicKey,
			Purpose: keystore.PurposePoisonRecordKeyPair,
			State:   keystore.StateCurrent,
		}, true, nil
	case poisonSymmetricKey:
		return &keystore.KeyDescription{
			KeyID:   poisonSymmetricKey,
			Purpose: keystore.PurposePoisonRecordSymmetricKey,
		}, true, nil
	case legacyWebConfigKey:
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposeLegacy,
			State:   keystore.StateCurrent,
		}, true, nil
	}

	components := strings.Split(fileName, "_")

	if len(components) == 1 {
		id := strings.TrimSuffix(fileName, ".pub")

		return &keystore.KeyDescription{
			KeyID:    id,
			Purpose:  keystore.PurposeLegacy,
			ClientID: components[0],
			State:    keystore.StateCurrent,
		}, true, nil
	}

	//in case of one split result slice will have more than one element
	if len(components) < 2 {
		return nil, false, ErrUnrecognizedKeyPurpose
	}

	lastKeyPart := components[len(components)-1]
	penultimateKeyPart := components[len(components)-2]

	if lastKeyPart == "hmac" {
		return &keystore.KeyDescription{
			KeyID:    fileName,
			Purpose:  keystore.PurposeSearchHMAC,
			ClientID: strings.Join(components[:len(components)-1], "_"),
			State:    keystore.StateCurrent,
		}, true, nil
	}

	if lastKeyPart == "storage" {
		return &keystore.KeyDescription{
			KeyID:    fileName,
			Purpose:  keystore.PurposeStorageClientPrivateKey,
			ClientID: strings.Join(components[:len(components)-1], "_"),
			State:    keystore.StateCurrent,
		}, true, nil
	}

	if lastKeyPart == "storage.pub" {
		return &keystore.KeyDescription{
			KeyID:    fileName,
			Purpose:  keystore.PurposeStorageClientPublicKey,
			ClientID: strings.Join(components[:len(components)-1], "_"),
			State:    keystore.StateCurrent,
		}, true, nil
	}

	if lastKeyPart == "zone" {
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposeLegacy,
			State:   keystore.StateCurrent,
		}, true, nil
	}

	if lastKeyPart == "zone.pub" {
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposeLegacy,
			State:   keystore.StateCurrent,
		}, true, nil
	}

	if penultimateKeyPart == "storage" && lastKeyPart == "sym" {
		return &keystore.KeyDescription{
			KeyID:    fileName,
			Purpose:  keystore.PurposeStorageClientSymmetricKey,
			ClientID: strings.Join(components[:len(components)-2], "_"),
			State:    keystore.StateCurrent,
		}, true, nil
	}

	if penultimateKeyPart == "zone" && lastKeyPart == "sym" {
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposeLegacy,
			State:   keystore.StateCurrent,
		}, true, nil
	}

	if penultimateKeyPart == "log" && lastKeyPart == "key" {
		return &keystore.KeyDescription{
			KeyID:   fileName,
			Purpose: keystore.PurposeAuditLog,
			State:   keystore.StateCurrent,
		}, true, nil
	}

	if lastKeyPart == "server" || lastKeyPart == "server.pub" || lastKeyPart == "translator" || lastKeyPart == "translator.pub" {
		return &keystore.KeyDescription{
			KeyID:    fileName,
			Purpose:  keystore.PurposeLegacy,
			ClientID: components[0],
			State:    keystore.StateCurrent,
		}, true, nil
	}

	return nil, false, ErrUnrecognizedKeyPurpose
}
