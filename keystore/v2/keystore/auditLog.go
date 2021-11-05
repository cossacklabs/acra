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

const auditLogSymmetricKeyPath = "audit-log"

//
// AuditLogKeyStore  interface
//

// GetLogSecretKey retrieves audit log symmetric key.
func (s *ServerKeyStore) GetLogSecretKey() ([]byte, error) {
	log := s.log
	ring, err := s.OpenKeyRing(auditLogSymmetricKeyPath)
	if err != nil {
		log.WithError(err).Debug("Failed to open audit log key ring")
		return nil, err
	}
	symmetricKey, err := s.currentSymmetricKey(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to get current audit log key")
		return nil, err
	}
	return symmetricKey, nil
}

//
// AuditLogKeyGenerator interface
//

// GenerateLogKey generates new audit log symmetric key.
func (s *ServerKeyStore) GenerateLogKey() error {
	log := s.log
	ring, err := s.OpenKeyRingRW(auditLogSymmetricKeyPath)
	if err != nil {
		log.WithError(err).Debug("Failed to open audit log key ring")
		return err
	}
	_, err = s.newCurrentSymmetricKey(ring)
	if err != nil {
		log.WithError(err).Debug("Failed to generate audit log key")
		return err
	}
	return nil
}

func (s *ServerKeyStore) importLogKey(auditLogKey []byte) error {
	log := s.log
	ring, err := s.OpenKeyRingRW(auditLogSymmetricKeyPath)
	if err != nil {
		log.WithError(err).Debug("Failed to open audit log key ring")
		return err
	}
	err = s.addCurrentSymmetricKey(ring, auditLogKey)
	if err != nil {
		log.WithError(err).Debug("Failed to add audit log key")
		return err
	}
	return nil
}
