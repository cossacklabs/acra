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
	PurposePoisonRecordKeyPair       KeyPurpose = "poison_key"
	PurposeStorageClientKeyPair      KeyPurpose = "storage"
	PurposeStorageClientPublicKey    KeyPurpose = "public_storage"
	PurposeStorageClientPrivateKey   KeyPurpose = "private_storage"
	PurposeLegacy                    KeyPurpose = "legacy"
	PurposeUndefined                 KeyPurpose = "undefined"
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

// ExportMode constants describe which data to export from key storage.
type ExportMode int

// ExportMode flags.
const (
	// Export only public key data.
	ExportPublicOnly ExportMode = 0
	// Export private and public key data.
	ExportPrivateKeys = (1 << iota)
	ExportAllKeys     = (2 << iota)
)

// KeysBackup struct that store keys for poison records and all client's keys
type KeysBackup struct {
	Keys []byte
	Data []byte
}

// Key kind constants:
const (
	KeyPoisonKeypair   = "poison-keypair"
	KeyPoisonSymmetric = "poison-symmetric"
	KeyPoisonPublic    = "poison-public"
	KeyPoisonPrivate   = "poison-private"
	KeyStorageKeypair  = "storage-keypair"
	KeyStoragePublic   = "storage-public"
	KeyStoragePrivate  = "storage-private"

	KeySymmetric = "symmetric-key"
	KeySearch    = "hmac-key"

	// KeyPath temporal value used to save backward compatibility for acra-keys export command
	KeyPath = "path"
)

// ExportID represent KeyKind and KeyContext for Exporter
type ExportID struct {
	KeyKind   string
	ContextID []byte
}

// Exporter interface for acra-keys export command
type Exporter interface {
	Export(exportIDs []ExportID, mode ExportMode) (*KeysBackup, error)
}

// Importer interface for acra-keys import command
type Importer interface {
	Import(*KeysBackup) ([]KeyDescription, error)
}

// Backup interface for export/import KeyStore
type Backup interface {
	Exporter
	Importer
}

// KeyOwnerType define type key owners. Defined to avoid function overrides for clientID keys and allow to
// define one function for several key owners
type KeyOwnerType int

// Set of values for KeyOwnerType
const (
	KeyOwnerTypeClient = iota
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
}

// SymmetricEncryptionKeyStoreGenerator interface methods responsible for generation encryption symmetric keys
type SymmetricEncryptionKeyStoreGenerator interface {
	GenerateClientIDSymmetricKey(id []byte) error
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
	Context  []byte
	Purpose  KeyPurpose
}

// NewEmptyKeyContext create new empty key context
func NewEmptyKeyContext(ctx []byte) KeyContext {
	return KeyContext{
		Context: ctx,
	}
}

// NewKeyContext create new key context with key purpose and pure context
func NewKeyContext(purpose KeyPurpose, ctx []byte) KeyContext {
	return KeyContext{
		Purpose: purpose,
		Context: ctx,
	}
}

// NewClientIDKeyContext create new key context with key purpose and clientID
func NewClientIDKeyContext(purpose KeyPurpose, clientID []byte) KeyContext {
	return KeyContext{
		Purpose:  purpose,
		ClientID: clientID,
	}
}

// GetKeyContextFromContext return byte context depending on provided options
func GetKeyContextFromContext(keyContext KeyContext) []byte {
	if keyContext.ClientID != nil {
		return keyContext.ClientID
	}
	if keyContext.Context != nil {
		return keyContext.Context
	}
	return nil
}

// String implementation of Stringer interface for KeyContext
func (ctx KeyContext) String() string {
	if ctx.ClientID != nil {
		return string(ctx.ClientID)
	}
	if ctx.Context != nil {
		return string(ctx.Context)
	}
	return "empty KeyContext"
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
	encrypted, _, err := encryptor.scell.Protect(key, GetKeyContextFromContext(keyContext))
	return encrypted, err
}

// Decrypt return decrypted key using masterKey and context.
func (encryptor *SCellKeyEncryptor) Decrypt(ctx context.Context, key []byte, keyContext KeyContext) ([]byte, error) {
	return encryptor.scell.Unprotect(key, nil, GetKeyContextFromContext(keyContext))
}

// TransportKeyStore provides access to transport keys. It is used by acra-connector tool.
type TransportKeyStore interface {
	AuditLogKeyStore
	CheckIfPrivateKeyExists(clientID []byte) (bool, error)
}

// PublicKeyStore provides access to storage public keys, used to encrypt data for storage.
type PublicKeyStore interface {
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
	GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error)
	GetServerDecryptionPrivateKeys(id []byte) ([]*keys.PrivateKey, error)
}

// StorageKeyCreation enables creation of new storage key pairs and rotation of existing ones.
type StorageKeyCreation interface {
	// Generates a new storage key pair for given client ID.
	GenerateDataEncryptionKeys(clientID []byte) error
	// Sets storage key pair for given client ID.
	SaveDataEncryptionKeys(clientID []byte, keypair *keys.Keypair) error
}

// StorageKeyDestruction enables destruction of created keys.
type StorageKeyDestruction interface {
	DestroyPoisonKeyPair() error
	DestroyPoisonSymmetricKey() error
	DestroyClientIDEncryptionKeyPair(clientID []byte) error
	DestroyClientIDSymmetricKey(clientID []byte) error
	DestroyHmacSecretKey(clientID []byte) error
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
	StorageKeyDestruction
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
// "ClientID" and "AdditionalContext" are filled in where relevant.
type KeyDescription struct {
	ID       string
	Purpose  KeyPurpose
	ClientID []byte `json:",omitempty"`
}

// TranslationKeyStore enables AcraStruct translation. It is used by acra-translator tool.
type TranslationKeyStore interface {
	DecryptionKeyStore
	AuditLogKeyStore

	CacheOnStart() error
}
