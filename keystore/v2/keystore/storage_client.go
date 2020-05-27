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

package keystore

import (
	"path/filepath"

	"github.com/cossacklabs/themis/gothemis/keys"
)

//
// PublicKeyStore interface (clients)
//

// GetClientIDEncryptionPublicKey retrieves public key used to encrypt data by given client.
func (s *ServerKeyStore) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.clientStorageKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for client")
		return nil, err
	}
	publicKey, err := s.currentPairPublicKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current storage public key for client")
		return nil, err
	}
	return publicKey, nil
}

//
// PrivateKeyStore interface (clients)
//

// GetServerDecryptionPrivateKey retrieves private key used to decrypt data by given client.
func (s *ServerKeyStore) GetServerDecryptionPrivateKey(clientID []byte) (*keys.PrivateKey, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.clientStorageKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for client")
		return nil, err
	}
	privateKey, err := s.currentPairPrivateKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current storage private key for client")
		return nil, err
	}
	return privateKey, nil
}

// GetServerDecryptionPrivateKeys retrieves all private key used to decrypt data by given client.
// The keys are returned from newest to oldest.
func (s *ServerKeyStore) GetServerDecryptionPrivateKeys(clientID []byte) ([]*keys.PrivateKey, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.clientStorageKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for client")
		return nil, err
	}
	privateKeys, err := s.allPairPrivateKeys(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get storage private keys for client")
		return nil, err
	}
	return privateKeys, nil
}

//
// StorageKeyCreation interface (clients)
//

const clientPrefix = "client"
const storageSuffix = "storage"

func (s *ServerKeyStore) clientStorageKeyPairPath(clientID []byte) string {
	return filepath.Join(clientPrefix, string(clientID), storageSuffix)
}

// GenerateDataEncryptionKeys generates new storage keypair used by given client.
func (s *ServerKeyStore) GenerateDataEncryptionKeys(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientStorageKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for client")
		return err
	}
	_, err = s.newCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("failed to generate storage key pair for client")
		return err
	}
	return nil
}

// SaveDataEncryptionKeys overwrites storage keypair used by given client.
func (s *ServerKeyStore) SaveDataEncryptionKeys(clientID []byte, keypair *keys.Keypair) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientStorageKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for client")
		return err
	}
	err = s.addCurrentKeyPair(ring, keypair)
	if err != nil {
		log.WithError(err).Debug("failed to set storage key pair for client")
		return err
	}
	return nil
}
