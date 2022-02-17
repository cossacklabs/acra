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

// GetPoisonKeyPair retrieves current poison record key pair.
// The keypair is created if it does not exist yet.
func (s *ServerKeyStore) GetPoisonKeyPair() (*keys.Keypair, error) {
	ring, err := s.OpenKeyRingRW(poisonKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonKeyPath).
			Debug("failed to open poison key ring")
		return nil, err
	}
	keypair, err := s.currentKeyPair(ring)
	if err == api.ErrNoCurrentKey {
		s.log.Debug("Generate poison record key pair")
		return s.newCurrentKeyPair(ring)
	}
	if err != nil {
		s.log.WithError(err).Debug("failed to get current poison record key pair")
		return nil, err
	}
	return keypair, nil
}

// GetPoisonPrivateKeys returns all private keys used to decrypt poison records, from newest to oldest.
// If a poison record does not exist, it is created and its sole private key is returned.
// Returns a list of private poison keys (possibly empty), or an error if decryption fails.
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
		keypair, err := s.newCurrentKeyPair(ring)
		if err != nil {
			s.log.WithError(err).Debug("Failed to generated poison record key")
		}
		privateKeys = []*keys.PrivateKey{keypair.Private}
	}
	return privateKeys, nil
}

// GetPoisonSymmetricKeys returns all symmetric keys used to decrypt poison records with AcraBlock, from newest to oldest.
// If a poison record does not exist, it is created and its sole symmetric key is returned.
// Returns a list of symmetric poison keys (possibly empty), or an error if decryption fails.
func (s *ServerKeyStore) GetPoisonSymmetricKeys() ([][]byte, error) {
	ring, err := s.OpenKeyRingRW(poisonSymmetricKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonSymmetricKeyPath).
			Debug("Failed to open poison key ring")
		return nil, err
	}

	symmetricKeys, err := s.allSymmetricKeys(ring)
	if err != nil {
		s.log.WithError(err).Debug("Failed to get poison record symmetric keys")
		if err := s.GeneratePoisonRecordSymmetricKey(); err != nil {
			return nil, err
		}
		return s.allSymmetricKeys(ring)
	}
	return symmetricKeys, nil
}

// GetPoisonSymmetricKey returns latest symmetric key for encryption of poison records with AcraBlock.
// If a poison record does not exist, it is created and its sole symmetric key is returned.
func (s *ServerKeyStore) GetPoisonSymmetricKey() ([]byte, error) {
	ring, err := s.OpenKeyRingRW(poisonSymmetricKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", poisonSymmetricKeyPath).
			Debug("Failed to open poison key ring")
		return nil, err
	}

	symmetricKey, err := s.currentSymmetricKey(ring)
	if err != nil {
		s.log.WithError(err).Debug("Failed to get current poison record symmetric key")
		if err := s.GeneratePoisonRecordSymmetricKey(); err != nil {
			return nil, err
		}
		return s.currentSymmetricKey(ring)
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

// GeneratePoisonRecordSymmetricKey generates new poison record symmetric key.
func (s *ServerKeyStore) GeneratePoisonRecordSymmetricKey() error {
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
