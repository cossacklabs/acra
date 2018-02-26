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
	"errors"
	"github.com/cossacklabs/themis/gothemis/keys"
	"strings"
)

const (
	DEFAULT_KEY_DIR_SHORT = ".acrakeys"
	VALID_CHARS           = "_- "
	MAX_CLIENT_ID_LENGTH  = 256
	MIN_CLIENT_ID_LENGTH  = 5
)

var ErrInvalidClientId = errors.New("Invalid client id")

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

	GenerateProxyKeys(id []byte) error
	GenerateServerKeys(id []byte) error
	// generate key pair for data encryption/decryption
	GenerateDataEncryptionKeys(id []byte) error

	GetPoisonKeyPair() (*keys.Keypair, error)

	Reset()
}
