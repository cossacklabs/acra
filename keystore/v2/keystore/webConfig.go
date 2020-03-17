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
)

//
// WebConfigKeyStore interface
//

const authKeyPath = "authentication"

// GetAuthKey retrieves current symmetric key for Acra Web Config.
// The key is created it if it does not exist yet, or recreated if "remove" is true.
func (s *ServerKeyStore) GetAuthKey(remove bool) ([]byte, error) {
	ring, err := s.OpenKeyRingRW(authKeyPath)
	if err != nil {
		s.log.WithError(err).WithField("path", authKeyPath).
			Debug("failed to open authentication key ring")
		return nil, err
	}
	if remove {
		s.log.Info("new authentication key for AcraWebconfig requested")
		return s.newCurrentSymmetricKey(ring)
	}
	key, err := s.currentSymmetricKey(ring)
	if err == api.ErrNoCurrentKey {
		s.log.Info("generate authentication key for AcraWebconfig")
		return s.newCurrentSymmetricKey(ring)
	}
	if err != nil {
		s.log.WithError(err).Debug("failed to get current authentication key")
		return nil, err
	}
	return key, nil
}
