/*
Copyright 2016, Cossack Labs Limited

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

// Package keystore describes various KeyStore interfaces. KeyStore is responsible for storing and accessing
// encryption keys: both transport ans storage. Keystore abstracts from real key storage (it might be folder in
// file system or remote KMS). Keystore is responsible for generating, reading and decrypting specific keys.
package keystore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
)

// KeyStore-related constants.
const (
	// DefaultKeyDirShort
	DefaultKeyDirShort   = ".acrakeys"
	ValidChars           = "_- "
	MaxClientIDLength    = 256
	MinClientIDLength    = 5
	AcraMasterKeyVarName = "ACRA_MASTER_KEY"
	// SymmetricKeyLength in bytes for master key
	SymmetricKeyLength = 32
	NoKeyFoundExit     = true
)

// KeyPurpose describe usage of specific key
type KeyPurpose string

func (p KeyPurpose) String() string {
	return string(p)
}

// Supported key purposes
const (
	PurposeSearchHMAC                KeyPurpose = "search_hmac"
	PurposeAuditLog                  KeyPurpose = "audit_log"
	PurposePoisonRecordSymmetricKey  KeyPurpose = "poison_sym_key"
	PurposeStorageClientSymmetricKey KeyPurpose = "storage_sym_key"
	PurposeStorageZoneSymmetricKey   KeyPurpose = "zone_sym_key"
	PurposePoisonRecordKeyPair       KeyPurpose = "poison_key"
	PurposeStorageClientKeyPair      KeyPurpose = "storage"
	PurposeStorageClientPublicKey    KeyPurpose = "public_storage"
	PurposeStorageClientPrivateKey   KeyPurpose = "private_storage"
	PurposeStorageZoneKeyPair        KeyPurpose = "zone"
	PurposeStorageZonePrivateKey     KeyPurpose = "private_zone"
	PurposeStorageZonePublicKey      KeyPurpose = "public_zone"
	PurposeLegacy                    KeyPurpose = "legacy"
)

// Errors returned during accessing to client id or master key.
var (
	ErrInvalidClientID          = errors.New("invalid client ID")
	ErrEmptyMasterKey           = errors.New("master key is empty")
	ErrMasterKeyIncorrectLength = fmt.Errorf("master key must have %v length in bytes", SymmetricKeyLength)
	ErrCacheIsNotSupportedV2    = errors.New("keystore cache is not supported for keystore v2")
)

// Key struct store content of keypair or some symmetric key
type Key struct {
	Name    string
	Content []byte
}

// KeysBackup struct that store keys for poison records and all client's/zone's keys
type KeysBackup struct {
	MasterKey []byte
	Keys      []byte
}

// Backup interface for export/import KeyStore
type Backup interface {
	Export() (*KeysBackup, error)
	Import(*KeysBackup) error
}

// KeyOwnerType define type key owners. Defined to avoid function overrides for clientID/zoneID keys and allow to
// define one function for several key owners
type KeyOwnerType int

// Set of values for KeyOwnerType
const (
	KeyOwnerTypeClient = iota
	KeyOwnerTypeZone   = iota
)

// ErrKeysNotFound used if can't find key or keys
var ErrKeysNotFound = errors.New("keys not found")

// HmacKeyStore interface to fetch keys for hma calculation
type HmacKeyStore interface {
	GetHMACSecretKey(id []byte) ([]byte, error)
}

// HmacKeyGenerator is able to generate keys for HmacKeyStore.
type HmacKeyGenerator interface {
	GenerateHmacKey(id []byte) error
}

// SymmetricEncryptionKeyStore interface describe access methods to encryption symmetric keys
type SymmetricEncryptionKeyStore interface {
	GetClientIDSymmetricKeys(id []byte) ([][]byte, error)
	GetClientIDSymmetricKey(id []byte) ([]byte, error)
	GetZoneIDSymmetricKeys(id []byte) ([][]byte, error)
	GetZoneIDSymmetricKey(id []byte) ([]byte, error)
}

// SymmetricEncryptionKeyStoreGenerator interface methods responsible for generation encryption symmetric keys
type SymmetricEncryptionKeyStoreGenerator interface {
	GenerateClientIDSymmetricKey(id []byte) error
	GenerateZoneIDSymmetricKey(id []byte) error
}

// PoisonKeyGenerator is responsible for generation of poison keys.
type PoisonKeyGenerator interface {
	GeneratePoisonSymmetricKey() error
	GeneratePoisonKeyPair() error
}

// AuditLogKeyStore keeps symmetric keys for audit log signtures.
type AuditLogKeyStore interface {
	GetLogSecretKey() ([]byte, error)
}

// AuditLogKeyGenerator is able to generate keys for AuditLogKeyStore.
type AuditLogKeyGenerator interface {
	GenerateLogKey() error
}

// GenerateSymmetricKey return new generated symmetric key that must used in keystore as master key and will comply
// our requirements.
func GenerateSymmetricKey() ([]byte, error) {
	key := make([]byte, SymmetricKeyLength)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != SymmetricKeyLength {
		return nil, ErrMasterKeyIncorrectLength
	}
	return key, nil
}

// ValidateID checks that clientID length is within required limits and
// clientID contains only valid chars (digits, letters, -, _, ' ').
func ValidateID(clientID []byte) bool {
	if len(clientID) < MinClientIDLength || len(clientID) > MaxClientIDLength {
		return false
	}
	// letters, digits, ValidChars = '-', '_', ' '
	for _, c := range string(clientID) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune(ValidChars, c) {
			return false
		}
	}
	return true
}

// ValidateMasterKey do validation of symmetric master key and return nil if pass check.
func ValidateMasterKey(key []byte) error {
	if len(key) < SymmetricKeyLength {
		return ErrMasterKeyIncorrectLength
	}
	return nil
}

// GetMasterKeyFromEnvironment return master key from environment variable with name AcraMasterKeyVarName
func GetMasterKeyFromEnvironment() (key []byte, err error) {
	return GetMasterKeyFromEnvironmentVariable(AcraMasterKeyVarName)
}

// GetMasterKeyFromEnvironmentVariable return master key from specified environment variable.
func GetMasterKeyFromEnvironmentVariable(varname string) ([]byte, error) {
	b64value := os.Getenv(varname)
	if len(b64value) == 0 {
		log.Warnf("%v environment variable is not set", varname)
		return nil, ErrEmptyMasterKey
	}
	key, err := base64.StdEncoding.DecodeString(b64value)
	if err != nil {
		log.WithError(err).Warnf("Failed to decode %s", varname)
		return nil, err
	}
	if err := ValidateMasterKey(key); err != nil {
		log.WithError(err).Warnf("Failed to validate %s", varname)
		return nil, err
	}
	return key, nil
}

// KeyContext contains generic key context for key operation
type KeyContext struct {
	ClientID []byte
	ZoneID   []byte
	Context  []byte
	Purpose  KeyPurpose
}

// NewEmptyKeyContext create new empty key context
func NewEmptyKeyContext() *KeyContext {
	return &KeyContext{}
}

// NewKeyContext create new key context with key purpose
func NewKeyContext(purpose KeyPurpose) *KeyContext {
	return &KeyContext{
		Purpose: purpose,
	}
}

// WithZoneID set zoneID to key context
func (k *KeyContext) WithZoneID(zoneID []byte) *KeyContext {
	k.ZoneID = zoneID
	return k
}

// WithClientID set clientID to key context
func (k *KeyContext) WithClientID(clientID []byte) *KeyContext {
	k.ClientID = clientID
	return k
}

// WithContext set encryption context to key context
func (k *KeyContext) WithContext(ctx []byte) *KeyContext {
	k.Context = ctx
	return k
}

// KeyEncryptor describes Encrypt and Decrypt interfaces.
type KeyEncryptor interface {
	Encrypt(ctx context.Context, key []byte, keyContext KeyContext) ([]byte, error)
	Decrypt(ctx context.Context, key []byte, keyContext KeyContext) ([]byte, error)
}

// SCellKeyEncryptor uses Themis Secure Cell with provided master key to encrypt and decrypt keys.
type SCellKeyEncryptor struct {
	scell *cell.SecureCell
}

// NewSCellKeyEncryptor creates new SCellKeyEncryptor object with masterKey using Themis Secure Cell in Seal mode.
func NewSCellKeyEncryptor(masterKey []byte) (*SCellKeyEncryptor, error) {
	return &SCellKeyEncryptor{scell: cell.New(masterKey, cell.ModeSeal)}, nil
}

// Encrypt return encrypted key using masterKey and context.
func (encryptor *SCellKeyEncryptor) Encrypt(ctx context.Context, key []byte, keyContext KeyContext) ([]byte, error) {
	encrypted, _, err := encryptor.scell.Protect(key, keyContext.Context)
	return encrypted, err
}

// Decrypt return decrypted key using masterKey and context.
func (encryptor *SCellKeyEncryptor) Decrypt(ctx context.Context, key []byte, keyContext KeyContext) ([]byte, error) {
	return encryptor.scell.Unprotect(key, nil, keyContext.Context)
}

// TransportKeyStore provides access to transport keys. It is used by acra-connector tool.
type TransportKeyStore interface {
	AuditLogKeyStore
	CheckIfPrivateKeyExists(clientID []byte) (bool, error)
}

// PublicKeyStore provides access to storage public keys, used to encrypt data for storage.
type PublicKeyStore interface {
	GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error)
	GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error)
}

// RecordProcessorKeyStore interface with required methods for RecordProcessor
type RecordProcessorKeyStore interface {
	GetPoisonPrivateKeys() ([]*keys.PrivateKey, error)
	GetPoisonSymmetricKeys() ([][]byte, error)
	GetPoisonSymmetricKey() ([]byte, error)
}

// DataEncryptorKeyStore interface with required methods for CryptoHandlers
type DataEncryptorKeyStore interface {
	PrivateKeyStore
	PublicKeyStore
}

// PrivateKeyStore provides access to storage private keys, used to decrypt stored data.
type PrivateKeyStore interface {
	SymmetricEncryptionKeyStore
	HasZonePrivateKey(id []byte) bool
	GetZonePrivateKey(id []byte) (*keys.PrivateKey, error)
	GetZonePrivateKeys(id []byte) ([]*keys.PrivateKey, error)
	GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error)
	GetServerDecryptionPrivateKeys(id []byte) ([]*keys.PrivateKey, error)
}

// StorageKeyCreation enables creation of new storage key pairs and rotation of existing ones.
type StorageKeyCreation interface {
	// Generates a new storage key pair for given client ID.
	GenerateDataEncryptionKeys(clientID []byte) error
	// Sets storage key pair for given client ID.
	SaveDataEncryptionKeys(clientID []byte, keypair *keys.Keypair) error
	// Creates a new zone along with a key.
	// Returns new zone ID, its public key data, error.
	GenerateZoneKey() ([]byte, []byte, error)
	// Replaces the current key pair for given zone ID.
	SaveZoneKeypair(zoneID []byte, keypair *keys.Keypair) error
	// Generates a new key pair and replaces the current key pair for given zone ID.
	// Returns new publie key data, error.
	RotateZoneKey(zoneID []byte) ([]byte, error)
	// Generates a new symetric key and replaces the current key for given zone ID.
	// Returns new key data, error.
	RotateSymmetricZoneKey(zoneID []byte) error
}

// DecryptionKeyStore enables AcraStruct decryption. It is used by acra-server.
type DecryptionKeyStore interface {
	PublicKeyStore
	PrivateKeyStore
	PoisonKeyStore
	HmacKeyStore
}

// StorageKeyGenerator is able to generate keys for Acra CE and Acra EE.
type StorageKeyGenerator interface {
	StorageKeyCreation
	SymmetricEncryptionKeyStoreGenerator
}

// KeyMaking enables keystore initialization. It is used by acra-keymaker tool.
type KeyMaking interface {
	StorageKeyCreation
	PoisonKeyGenerator
	AuditLogKeyGenerator
	HmacKeyGenerator
	SymmetricEncryptionKeyStoreGenerator
}

// PoisonKeyStore provides access to poison record key pairs.
type PoisonKeyStore interface {
	// Reads current poison record key pair, returning ErrKeysNotFound if it
	// does not exist yet.
	GetPoisonKeyPair() (*keys.Keypair, error)
	GetPoisonPrivateKeys() ([]*keys.PrivateKey, error)
	GetPoisonSymmetricKeys() ([][]byte, error)
	GetPoisonSymmetricKey() ([]byte, error)
}

// PoisonKeyStorageAndGenerator has all methods to create and retrieve various
// keys dedicated to poison records.
type PoisonKeyStorageAndGenerator interface {
	PoisonKeyStore
	PoisonKeyGenerator
}

// ServerKeyStore enables AcraStruct encryption, decryption,
// and secure communication of acra-server with other services.
type ServerKeyStore interface {
	DecryptionKeyStore
	StorageKeyCreation
	AuditLogKeyStore
	SymmetricEncryptionKeyStoreGenerator

	CacheOnStart() error
	ListKeys() ([]KeyDescription, error)
	Reset()
}

// KeyDescription describes a key in the keystore.
//
// "ID" is unique string that can be used to identify this key set in the keystore.
// "Purpose" is short human-readable description of the key purpose.
// "ClientID" and "ZoneID" are filled in where relevant.
type KeyDescription struct {
	ID       string
	Purpose  KeyPurpose
	ClientID []byte `json:",omitempty"`
	ZoneID   []byte `json:",omitempty"`
}

// TranslationKeyStore enables AcraStruct translation. It is used by acra-translator tool.
type TranslationKeyStore interface {
	DecryptionKeyStore
	AuditLogKeyStore

	CacheOnStart() error
}
