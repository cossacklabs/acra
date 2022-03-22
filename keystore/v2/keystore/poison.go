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
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/themis/gothemis/keys"
)

//
// PoisonKeyStore interface
//
const (
	poisonSymmetricKeyPath = "poison-record-sym"
	poisonKeyPath          = "poison-record"
)

// GetPoisonKeyPair retrieves current poison EC keypair.
// Returns ErrKeysNotFound if the keypair doesn't exist.
func (s *ServerKeyStore) GetPoisonKeyPair() (*keys.Keypair, error) {
	ring, err := s.OpenKeyRingRW(poisonKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonKeyPath).
			Debug("failed to open poison key ring")
		return nil, err
	}
	keypair, err := s.currentKeyPair(ring)
	if err == api.ErrNoCurrentKey {
		return nil, keystore.ErrKeysNotFound
	}
	if err != nil {
		s.log.WithError(err).Debug("failed to get current poison record key pair")
		return nil, err
	}
	return keypair, nil
}

// GetPoisonPrivateKeys returns all private keys used to decrypt poison records,
// from newest to oldest.
// Returns ErrKeysNotFound if the keys don't exist.
func (s *ServerKeyStore) GetPoisonPrivateKeys() ([]*keys.PrivateKey, error) {
	ring, err := s.OpenKeyRingRW(poisonKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonKeyPath).
			Debug("Failed to open poison key ring")
		return nil, err
	}
	privateKeys, err := s.allPairPrivateKeys(ring)
	if err != nil {
		s.log.WithError(err).Debug("Failed to get poison record keys")
		return nil, err
	}
	if len(privateKeys) == 0 {
		return nil, keystore.ErrKeysNotFound
	}
	return privateKeys, nil
}

// GetPoisonSymmetricKeys returns all symmetric keys used to decrypt poison
// records with AcraBlock, from newest to oldest.
// Returns ErrKeysNotFound if the keys don't exist.
func (s *ServerKeyStore) GetPoisonSymmetricKeys() ([][]byte, error) {
	ring, err := s.OpenKeyRingRW(poisonSymmetricKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonSymmetricKeyPath).
			Debug("Failed to open poison key ring")
		return nil, err
	}

	symmetricKeys, err := s.allSymmetricKeys(ring)
	if err != nil {
		return nil, err
	}
	if len(symmetricKeys) == 0 {
		return nil, keystore.ErrKeysNotFound
	}
	return symmetricKeys, nil
}

// GetPoisonSymmetricKey returns latest symmetric key for encryption of poison
// records with AcraBlock.
// Returns ErrKeysNotFound if the keys don't exist.
func (s *ServerKeyStore) GetPoisonSymmetricKey() ([]byte, error) {
	ring, err := s.OpenKeyRingRW(poisonSymmetricKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonSymmetricKeyPath).
			Debug("Failed to open poison key ring")
		return nil, err
	}

	symmetricKey, err := s.currentSymmetricKey(ring)
	if err == api.ErrNoCurrentKey {
		return nil, keystore.ErrKeysNotFound
	}
	if err != nil {
		return nil, err
	}
	return symmetricKey, nil
}

func (s *ServerKeyStore) savePoisonKeyPair(keypair *keys.Keypair) error {
	ring, err := s.OpenKeyRingRW(poisonKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonKeyPath).
			Debug("failed to open poison key ring")
		return err
	}
	err = s.addCurrentKeyPair(ring, keypair)
	if err != nil {
		s.log.WithError(err).Debug("failed to set current poison record key pair")
		return err
	}
	return nil
}

// GeneratePoisonSymmetricKey generates new poison record symmetric key.
func (s *ServerKeyStore) GeneratePoisonSymmetricKey() error {
	log := s.log
	ring, err := s.OpenKeyRingRW(poisonSymmetricKeyPath)
	if err != nil {
		log.WithError(err).Debug("Failed to open symmetric poison record key ring")
		return err
	}
	_, err = s.newCurrentSymmetricKey(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to generate poison record symmetric key")
		return err
	}
	return nil
}

func (store *ServerKeyStore) GeneratePoisonKeyPair() error {
	ring, err := store.OpenKeyRingRW(poisonKeyPath)
	if err != nil {
		store.log.WithError(err).Debug("Failed to open poison record key ring")
		return err
	}
	_, err = store.newCurrentKeyPair(ring)
	return err
}

func (s *ServerKeyStore) importPoisonRecordSymmetricKey(poisonKey []byte) error {
	log := s.log
	ring, err := s.OpenKeyRingRW(poisonSymmetricKeyPath)
	if err != nil {
		log.WithError(err).Debug("Failed to open symmetric poison record key ring")
		return err
	}
	err = s.addCurrentSymmetricKey(ring, poisonKey)
	if err != nil {
		log.WithError(err).Debug("Failed to add poison record symmetric key")
		return err
	}
	return nil
}
