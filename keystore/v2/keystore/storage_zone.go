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

	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
)

//
// PublicKeyStore interface (zones)
//

// GetZonePublicKey retrieves public key used to encrypt data in given zone.
func (s *ServerKeyStore) GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error) {
	log := s.log.WithField("zoneID", zoneID)
	ring, err := s.OpenKeyRing(s.zoneStorageKeyPairPath(zoneID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for zone")
		return nil, err
	}
	publicKey, err := s.currentPairPublicKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current storage public key for zone")
		return nil, err
	}
	return publicKey, nil
}

//
// PrivateKeyStore interface (zones)
//

// GetZonePrivateKey retrieves private key used to decrypt data in given zone.
func (s *ServerKeyStore) GetZonePrivateKey(zoneID []byte) (*keys.PrivateKey, error) {
	log := s.log.WithField("zoneID", zoneID)
	ring, err := s.OpenKeyRing(s.zoneStorageKeyPairPath(zoneID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for zone")
		return nil, err
	}
	privateKey, err := s.currentPairPrivateKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current storage private key for zone")
		return nil, err
	}
	return privateKey, nil
}

// GetZonePrivateKeys retrieves all private key used to decrypt data in given zone.
// The keys are returned from newest to oldest.
func (s *ServerKeyStore) GetZonePrivateKeys(zoneID []byte) ([]*keys.PrivateKey, error) {
	log := s.log.WithField("zoneID", zoneID)
	ring, err := s.OpenKeyRing(s.zoneStorageKeyPairPath(zoneID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for zone")
		return nil, err
	}
	privateKeys, err := s.allPairPrivateKeys(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get storage private key for zone")
		return nil, err
	}
	return privateKeys, nil
}

// HasZonePrivateKey returns true if there is a private key used to decrypt data in given zone.
func (s *ServerKeyStore) HasZonePrivateKey(zoneID []byte) bool {
	ring, err := s.OpenKeyRing(s.zoneStorageKeyPairPath(zoneID))
	if err != nil {
		return false
	}
	present, _ := s.hasCurrentKey(ring)
	return present
}

//
// StorageKeyCreation interface (zones)
//

const zonePrefix = "client"

func (s *ServerKeyStore) zoneStorageKeyPairPath(zoneID []byte) string {
	return filepath.Join(zonePrefix, string(zoneID), storageSuffix)
}

// GenerateZoneKey generates new zone and a storage key for it.
// Returns zone ID followed by public key data.
func (s *ServerKeyStore) GenerateZoneKey() ([]byte, []byte, error) {
	var zoneID []byte
	for {
		zoneID = zone.GenerateZoneID()
		if !s.HasZonePrivateKey(zoneID) {
			break
		}
	}
	log := s.log.WithField("zoneID", zoneID)
	ring, err := s.OpenKeyRingRW(s.zoneStorageKeyPairPath(zoneID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for zone")
		return nil, nil, err
	}
	pair, err := s.newCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("failed to generate storage key pair for zone")
		return nil, nil, err
	}
	utils.FillSlice(0, pair.Private.Value)
	return zoneID, pair.Public.Value, nil
}

// SaveZoneKeypair overwrites storage keypair used in given zone.
func (s *ServerKeyStore) SaveZoneKeypair(zoneID []byte, keypair *keys.Keypair) error {
	log := s.log.WithField("zoneID", zoneID)
	ring, err := s.OpenKeyRingRW(s.zoneStorageKeyPairPath(zoneID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for zone")
		return err
	}
	err = s.addCurrentKeyPair(ring, keypair)
	if err != nil {
		log.WithError(err).Debug("failed to set storage key pair for zone")
		return err
	}
	return nil
}

// RotateZoneKey generates a new storage key pair for given zone.
// Returns new public key data.
func (s *ServerKeyStore) RotateZoneKey(zoneID []byte) ([]byte, error) {
	log := s.log.WithField("zoneID", zoneID)
	ring, err := s.OpenKeyRingRW(s.zoneStorageKeyPairPath(zoneID))
	if err != nil {
		log.WithError(err).Debug("failed to open storage key ring for zone")
		return nil, err
	}
	pair, err := s.newCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("failed to rotate storage key pair for zone")
		return nil, err
	}
	utils.FillSlice(0, pair.Private.Value)
	return pair.Public.Value, nil
}
