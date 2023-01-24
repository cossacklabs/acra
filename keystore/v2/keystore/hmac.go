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
// HmacKeyStore interface
//

// GetHMACSecretKey retrieves current symmetric key for token HMAC for given client.
func (s *ServerKeyStore) GetHMACSecretKey(clientID []byte) ([]byte, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.clientHMACKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open HMAC key ring for client")
		return nil, err
	}
	symmetricKey, err := s.currentSymmetricKey(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to get HMAC key for client")
		return nil, err
	}
	return symmetricKey, nil
}

//
// HmacKeyGenerator interface
//

const (
	hmacSymmetricSuffix = "hmac-sym"
)

func (s *ServerKeyStore) clientHMACKeyPath(clientID []byte) string {
	return filepath.Join(clientPrefix, string(clientID), hmacSymmetricSuffix)
}

// GenerateHmacKey generates new symmetric key for token HMAC for given client.
func (s *ServerKeyStore) GenerateHmacKey(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientHMACKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open HMAC key ring for client")
		return err
	}
	_, err = s.newCurrentSymmetricKey(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to generate HMAC key for client")
		return err
	}
	return nil
}

// DestroyHmacSecretKey destroy hmac secret key ring
func (s *ServerKeyStore) DestroyHmacSecretKey(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientHMACKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open HMAC key ring for client")
		return err
	}
	err = s.destroyCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to generate HMAC key for client")
		return err
	}
	return nil
}

func (s *ServerKeyStore) importHmacKey(clientID []byte, hmacKey []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.clientHMACKeyPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open HMAC key ring for client")
		return err
	}
	err = s.addCurrentSymmetricKey(ring, hmacKey)
	if err != nil {
		log.WithError(err).Debug("Failed to add HMAC key for client")
		return err
	}
	return nil
}
