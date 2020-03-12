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

const poisonKeyPath = "poison-record"

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
		s.log.Info("generate poison record key pair")
		return s.newCurrentKeyPair(ring)
	}
	if err != nil {
		s.log.WithError(err).Debug("failed to get current poison record key pair")
		return nil, err
	}
	return keypair, nil
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
