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

	connectorMode "github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/themis/gothemis/keys"
)

//
// TransportKeyStore interface (AcraConnector)
//

// GetPeerPublicKey retrieves AcraConnector transport public key, depending on AcraConnector mode:
// - AcraServerMode: transport public key for AcraServer
// - AcraTranslatorMode: transport public key for AcraTranslator
// The "clientID" argument is ignored. It always uses AcraConnector's clientID.
func (c *ConnectorKeyStore) GetPeerPublicKey([]byte) (*keys.PublicKey, error) {
	log := c.log.WithField("clientID", c.clientID).WithField("mode", c.mode)
	var path string
	switch c.mode {
	case connectorMode.AcraServerMode:
		path = c.serverTransportKeyPairPath(c.clientID)
	case connectorMode.AcraTranslatorMode:
		path = c.translatorTransportKeyPairPath(c.clientID)
	default:
		return nil, fmt.Errorf("unsupported ConnectorMode: %v", c.mode)
	}
	ring, err := c.OpenKeyRing(path)
	if err != nil {
		log.WithError(err).Debug("failed to open connector transport key ring")
		return nil, err
	}
	publicKey, err := c.currentPairPublicKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current connector transport public key")
		return nil, err
	}
	return publicKey, nil
}

// GetPrivateKey retrieves AcraConnector transport private key for given clientID.
func (c *ConnectorKeyStore) GetPrivateKey(clientID []byte) (*keys.PrivateKey, error) {
	log := c.log.WithField("clientID", clientID)
	ring, err := c.OpenKeyRing(c.connectorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open connector transport key ring for client")
		return nil, err
	}
	privateKey, err := c.currentPairPrivateKey(ring)
	if err != nil {
		log.WithError(err).Debug("failed to get current connector transport private key for client")
		return nil, err
	}
	return privateKey, nil
}

// CheckIfPrivateKeyExists returns true if there is an AcraConnector transport private key for given clientID.
func (c *ConnectorKeyStore) CheckIfPrivateKeyExists(clientID []byte) (bool, error) {
	log := c.log.WithField("clientID", clientID)
	ring, err := c.OpenKeyRing(c.connectorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open connector transport key ring for client")
		return false, err
	}
	return c.hasCurrentKey(ring)
}

//
// TransportKeyCreation interface (AcraConnector)
//

func (s *ServerKeyStore) connectorTransportKeyPairPath(clientID []byte) string {
	return fmt.Sprintf("client/%s/transport/connector", string(clientID))
}

// GenerateConnectorKeys generates new AcraConnector transport keypair for given clientID.
func (s *ServerKeyStore) GenerateConnectorKeys(clientID []byte) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.connectorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open connector transport key ring for client")
		return err
	}
	_, err = s.newCurrentKeyPair(ring)
	if err != nil {
		log.WithError(err).Debug("failed to generate connector transport key pair for client")
		return err
	}
	return nil
}

// SaveConnectorKeypair overwrites AcraConnector transport keypair for given clientID.
func (s *ServerKeyStore) SaveConnectorKeypair(clientID []byte, keypair *keys.Keypair) error {
	log := s.log.WithField("clientID", clientID)
	ring, err := s.OpenKeyRingRW(s.connectorTransportKeyPairPath(clientID))
	if err != nil {
		log.WithError(err).Debug("failed to open connector transport key ring for client")
		return err
	}
	err = s.addCurrentKeyPair(ring, keypair)
	if err != nil {
		log.WithError(err).Debug("failed to set connector transport key pair for client")
		return err
	}
	return nil
}
