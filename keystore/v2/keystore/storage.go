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
)

//
// SymmetricEncryptionKeyStore interface
//

// GetClientIDSymmetricKeys retrieves all symmetric keys used to decrypt data by given client.
// The keys are returned from newest to oldest.
func (s *ServerKeyStore) GetClientIDSymmetricKeys(clientID []byte) ([][]byte, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.clientStorageSymmetricKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open symmetric storage key ring for client")
		return nil, err
	}
	symmetricKeys, err := s.allSymmetricKeys(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to get storage symmetric keys for client")
		return nil, err
	}
	return symmetricKeys, nil
}

// GetClientIDSymmetricKey retrieves latest symmetric key used to encrypt data by given client
func (s *ServerKeyStore) GetClientIDSymmetricKey(clientID []byte) ([]byte, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.clientStorageSymmetricKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open symmetric storage key ring for client")
		return nil, err
	}
	symmetricKey, err := s.currentSymmetricKey(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to get current storage symmetric key for client")
		return nil, err
	}
	return symmetricKey, nil
}

//
// SymmetricEncryptionKeyStoreGenerator interface
//

const (
	storageSymmetricSuffix = "storage-sym"
)

func (s *ServerKeyStore) clientStorageSymmetricKeyPath(clientID []byte) string {
	return filepath.Join(clientPrefix, string(clientID), storageSymmetricSuffix)
}

// GenerateClientIDSymmetricKey generates new storage symmetric key used by given client.
func (s *ServerKeyStore) GenerateClientIDSymmetricKey(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientStorageSymmetricKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open symmetric storage key ring for client")
		return err
	}
	_, err = s.newCurrentSymmetricKey(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to generate storage symmetric key for client")
		return err
	}
	return nil
}

// DestroyClientIDSymmetricKey destroy client storage symmetric key ring
func (s *ServerKeyStore) DestroyClientIDSymmetricKey(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientStorageSymmetricKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open symmetric storage key ring for client")
		return err
	}
	err = s.destroyCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to generate storage symmetric key for client")
		return err
	}
	return nil
}

func (s *ServerKeyStore) importClientIDSymmetricKey(clientID []byte, storageKey []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientStorageSymmetricKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open symmetric storage key ring for client")
		return err
	}
	err = s.addCurrentSymmetricKey(ring, storageKey)
	if err != nil {
		log.WithError(err).Debug("Failed to add storage symmetric key for client")
		return err
	}
	return nil
}
