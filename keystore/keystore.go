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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// KeyStore-related constants.
const (
	// DefaultKeyDirShort
	DefaultKeyDirShort   = ".acrakeys"
	ValidChars           = "_- "
	MaxClientIDLength    = 256
	MinClientIDLength    = 5
	BasicAuthKeyLength   = 32
	AcraMasterKeyVarName = "ACRA_MASTER_KEY"
	// SymmetricKeyLength in bytes for master key
	SymmetricKeyLength = 32
)

// Errors returned during accessing to client id or master key.
var (
	ErrInvalidClientID          = errors.New("invalid client ID")
	ErrEmptyMasterKey           = errors.New("master key is empty")
	ErrMasterKeyIncorrectLength = fmt.Errorf("master key must have %v length in bytes", SymmetricKeyLength)
)

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
	b64value := os.Getenv(AcraMasterKeyVarName)
	if len(b64value) == 0 {
		return nil, ErrEmptyMasterKey
	}
	key, err = base64.StdEncoding.DecodeString(b64value)
	if err != nil {
		return
	}
	if err = ValidateMasterKey(key); err != nil {
		return
	}
	return
}

// KeyEncryptor describes Encrypt and Decrypt interfaces.
type KeyEncryptor interface {
	Encrypt(key, context []byte) ([]byte, error)
	Decrypt(key, context []byte) ([]byte, error)
}

// SCellKeyEncryptor uses Themis Secure Cell with provided master key to encrypt and decrypt keys.
type SCellKeyEncryptor struct {
	scell *cell.SecureCell
}

// NewSCellKeyEncryptor creates new SCellKeyEncryptor object with masterKey using Themis Secure Cell in Seal mode.
func NewSCellKeyEncryptor(masterKey []byte) (*SCellKeyEncryptor, error) {
	return &SCellKeyEncryptor{scell: cell.New(masterKey, cell.CELL_MODE_SEAL)}, nil
}

// Encrypt return encrypted key using masterKey and context.
func (encryptor *SCellKeyEncryptor) Encrypt(key, context []byte) ([]byte, error) {
	encrypted, _, err := encryptor.scell.Protect(key, context)
	return encrypted, err
}

// Decrypt return decrypted key using masterKey and context.
func (encryptor *SCellKeyEncryptor) Decrypt(key, context []byte) ([]byte, error) {
	return encryptor.scell.Unprotect(key, nil, context)
}

// SecureSessionKeyStore describes KeyStore used for handling Themis Secure Session connection.
type SecureSessionKeyStore interface {
	GetPrivateKey(id []byte) (*keys.PrivateKey, error)
	GetPeerPublicKey(id []byte) (*keys.PublicKey, error)
}

// PublicKeyStore provide interface to fetch public keys to encrypt data
type PublicKeyStore interface {
	GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error)
	GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error)
}

// KeyStore describes any KeyStore that reads keys to handle Themis Secure Session connection,
// to encrypt and decrypt AcraStructs with and without Zones,
// to find Poison records.
// Moreover KeyStore can generate various Keys using ClientID.
// Save*Keypair methods save or overwrite existing keypair with new
// Genenerate*Keys - generate new keypair and save
type KeyStore interface {
	SecureSessionKeyStore
	GetZonePrivateKey(id []byte) (*keys.PrivateKey, error)
	HasZonePrivateKey(id []byte) bool
	GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error)

	// return id, public key, error
	GenerateZoneKey() ([]byte, []byte, error)
	SaveZoneKeypair(id []byte, keypair *keys.Keypair) error

	// return new_public_key, error
	RotateZoneKey(zoneID []byte) ([]byte, error)

	SaveConnectorKeypair(id []byte, keypair *keys.Keypair) error
	GenerateConnectorKeys(id []byte) error

	SaveServerKeypair(id []byte, keypair *keys.Keypair) error
	GenerateServerKeys(id []byte) error

	SaveTranslatorKeypair(id []byte, keypair *keys.Keypair) error
	GenerateTranslatorKeys(id []byte) error

	// generate key pair for data encryption/decryption
	GenerateDataEncryptionKeys(id []byte) error
	SaveDataEncryptionKeys(id []byte, keypair *keys.Keypair) error

	GetPoisonKeyPair() (*keys.Keypair, error)

	GetAuthKey(remove bool) ([]byte, error)
	Reset()
}
