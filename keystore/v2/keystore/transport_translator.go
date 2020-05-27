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
// TransportKeyStore interface (AcraTranslator)
//

// GetPeerPublicKey retrieves AcraTranslator transport public key for given clientID.
// This is public key corresponding to AcraConnector's private key.
func (t *TranslatorKeyStore) GetPeerPublicKey(clientID []byte) (*keys.PublicKey, error) {
	log := t.log.WithField("clientID", clientID)
	ring, err := t.OpenKeyRing(t.connectorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open translator transport key ring for client")
		return nil, err
	}
	publicKey, err := t.currentPairPublicKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current translator transport public key for client")
		return nil, err
	}
	return publicKey, nil
}

// GetPrivateKey retrieves AcraTranslator transport private key for given clientID.
func (t *TranslatorKeyStore) GetPrivateKey(clientID []byte) (*keys.PrivateKey, error) {
	log := t.log.WithField("clientID", clientID)
	ring, err := t.OpenKeyRing(t.translatorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open translator transport key ring for client")
		return nil, err
	}
	privateKey, err := t.currentPairPrivateKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current translator transport private key for client")
		return nil, err
	}
	return privateKey, nil
}

// CheckIfPrivateKeyExists returns true if there is an AcraTranslator transport private key for given clientID.
func (t *TranslatorKeyStore) CheckIfPrivateKeyExists(clientID []byte) (bool, error) {
	log := t.log.WithField("clientID", clientID)
	ring, err := t.OpenKeyRing(t.translatorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open translator transport key ring for client")
		return false, err
	}
	return t.hasCurrentKey(ring)
}

//
// TransportKeyCreation interface (AcraTranslator)
//

const translatorSuffix = "translator"

func (s *ServerKeyStore) translatorTransportKeyPairPath(clientID []byte) string {
	return filepath.Join(clientPrefix, string(clientID), transportSuffix, translatorSuffix)
}

// GenerateTranslatorKeys generates new AcraTranslator transport keypair for given clientID.
func (s *ServerKeyStore) GenerateTranslatorKeys(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.translatorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open translator transport key ring for client")
		return err
	}
	_, err = s.newCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("failed to generate translator transport key pair for client")
		return err
	}
	return nil
}

// SaveTranslatorKeypair overwrites AcraTranslator transport keypair for given clientID.
func (s *ServerKeyStore) SaveTranslatorKeypair(clientID []byte, keypair *keys.Keypair) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.translatorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open translator transport key ring for client")
		return err
	}
	err = s.addCurrentKeyPair(ring, keypair)
	if err != nil {
		log.WithError(err).Debug("failed to set translator transport key pair for client")
		return err
	}
	return nil
}

// DestroyTranslatorKeypair destroys currently used AcraTranslator transport keypair for given clientID.
func (s *ServerKeyStore) DestroyTranslatorKeypair(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.translatorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("Failed to open translator transport key ring for client")
		return err
	}
	err = s.destroyCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to destroy translator transport key pair for client")
		return err
	}
	return nil
}
