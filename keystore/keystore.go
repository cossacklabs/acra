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

const (
	DEFAULT_KEY_DIR_SHORT    = ".acrakeys"
	VALID_CHARS              = "_- "
	MAX_CLIENT_ID_LENGTH     = 256
	MIN_CLIENT_ID_LENGTH     = 5
	BASIC_AUTH_KEY_LENGTH    = 32
	ACRA_MASTER_KEY_VAR_NAME = "ACRA_MASTER_KEY"
	// SYMMETRIC_KEY_LENGTH in bytes for master key
	SYMMETRIC_KEY_LENGTH = 32
)

var ErrInvalidClientId = errors.New("invalid client id")
var ErrEmptyMasterKey = errors.New("master key is empty")
var ErrMasterKeyIncorrectLength = fmt.Errorf("master key must have %v length in bytes", SYMMETRIC_KEY_LENGTH)

// GenerateSymmetricKey return new generated symmetric key that must used in keystore as master key and will comply
// our requirements
func GenerateSymmetricKey() ([]byte, error) {
	key := make([]byte, SYMMETRIC_KEY_LENGTH)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != SYMMETRIC_KEY_LENGTH {
		return nil, ErrMasterKeyIncorrectLength
	}
	return key, nil
}

func ValidateId(client_id []byte) bool {
	if len(client_id) < MIN_CLIENT_ID_LENGTH || len(client_id) > MAX_CLIENT_ID_LENGTH {
		return false
	}
	// letters, digits, VALID_CHARS = '-', '_', ' '
	for _, c := range string(client_id) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune(VALID_CHARS, c) {
			return false
		}
	}
	return true
}

// ValidateMasterKey do validation of symmetric master key and return nil if pass check
func ValidateMasterKey(key []byte) error {
	if len(key) < SYMMETRIC_KEY_LENGTH {
		return ErrMasterKeyIncorrectLength
	}
	return nil
}

// GetMasterKeyFromEnvironment return master key from environment variable with name ACRA_MASTER_KEY_VAR_NAME
func GetMasterKeyFromEnvironment() (key []byte, err error) {
	b64value := os.Getenv(ACRA_MASTER_KEY_VAR_NAME)
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

type KeyEncryptor interface {
	Encrypt(key, context []byte) ([]byte, error)
	Decrypt(key, context []byte) ([]byte, error)
}

type SCellKeyEncryptor struct {
	scell *cell.SecureCell
}

func NewSCellKeyEncryptor(masterKey []byte) (*SCellKeyEncryptor, error) {
	return &SCellKeyEncryptor{scell: cell.New(masterKey, cell.CELL_MODE_SEAL)}, nil
}

// EncryptKey return encrypted key using masterKey and context
func (encryptor *SCellKeyEncryptor) Encrypt(key, context []byte) ([]byte, error) {
	encrypted, _, err := encryptor.scell.Protect(key, context)
	return encrypted, err
}

// DecryptKey return decrypted key using masterKey and context
func (encryptor *SCellKeyEncryptor) Decrypt(key, context []byte) ([]byte, error) {
	return encryptor.scell.Unprotect(key, nil, context)
}

type SecureSessionKeyStore interface {
	GetPrivateKey(id []byte) (*keys.PrivateKey, error)
	GetPeerPublicKey(id []byte) (*keys.PublicKey, error)
}

type KeyStore interface {
	SecureSessionKeyStore
	GetZonePrivateKey(id []byte) (*keys.PrivateKey, error)
	HasZonePrivateKey(id []byte) bool
	GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error)
	// return id, public key, error
	GenerateZoneKey() ([]byte, []byte, error)

	GenerateConnectorKeys(id []byte) error
	GenerateServerKeys(id []byte) error
	GenerateTranslatorKeys(id []byte) error

	// generate key pair for data encryption/decryption
	GenerateDataEncryptionKeys(id []byte) error
	GetPoisonKeyPair() (*keys.Keypair, error)

	GetAuthKey(remove bool) ([]byte, error)
	Reset()
}
