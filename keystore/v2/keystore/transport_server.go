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
	"fmt"

	"github.com/cossacklabs/themis/gothemis/keys"
)

//
// TransportKeyStore interface (AcraServer)
//

// GetPeerPublicKey retrieves AcraServer transport public key for given clientID.
// This is public key corresponding to AcraConnector's private key.
func (s *ServerKeyStore) GetPeerPublicKey(clientID []byte) (*keys.PublicKey, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.connectorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open transport key ring for client")
		return nil, err
	}
	publicKey, err := s.currentPairPublicKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current transport public key for client")
		return nil, err
	}
	return publicKey, nil
}

// GetPrivateKey retrieves AcraServer transport private key for given clientID.
func (s *ServerKeyStore) GetPrivateKey(clientID []byte) (*keys.PrivateKey, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.serverTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open transport key ring for client")
		return nil, err
	}
	privateKey, err := s.currentPairPrivateKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current transport private key for client")
		return nil, err
	}
	return privateKey, nil
}

// CheckIfPrivateKeyExists returns true if there is an AcraServer transport private key for given clientID.
func (s *ServerKeyStore) CheckIfPrivateKeyExists(clientID []byte) (bool, error) {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRing(s.serverTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open transport key ring for client")
		return false, err
	}
	return s.hasCurrentKey(ring)
}

//
// TransportKeyCreation interface (AcraServer)
//

func (s *ServerKeyStore) serverTransportKeyPairPath(clientID []byte) string {
	return fmt.Sprintf("client/%s/transport/server", string(clientID))
}

// GenerateServerKeys generates new AcraServer transport keypair for given clientID.
func (s *ServerKeyStore) GenerateServerKeys(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.serverTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open transport key ring for client")
		return err
	}
	_, err = s.newCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("failed to generate transport key pair for client")
		return err
	}
	return nil
}

// SaveServerKeypair overwrites AcraServer transport keypair for given clientID.
func (s *ServerKeyStore) SaveServerKeypair(clientID []byte, keypair *keys.Keypair) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.serverTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open transport key ring for client")
		return err
	}
	err = s.addCurrentKeyPair(ring, keypair)
	if err != nil {
		log.WithError(err).Debug("failed to set transport key pair for client")
		return err
	}
	return nil
}

// DestroyServerKeypair destroys currently used AcraServer transport keypair for given clientID.
func (s *ServerKeyStore) DestroyServerKeypair(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.serverTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open transport key ring for client")
		return err
	}
	err = s.destroyCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to destroy transport key pair for client")
		return err
	}
	return nil
}
