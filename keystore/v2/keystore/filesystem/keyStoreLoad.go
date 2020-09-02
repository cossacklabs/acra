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

package filesystem

import (
	backend "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
)

func (s *KeyStore) syncKeyRing(ring *KeyRing) error {
	if ring.pendingUpdates() {
		return s.writeKeyRing(ring)
	}
	return s.readKeyRing(ring)
}

func (s *KeyStore) readKeyRing(ring *KeyRing) (err error) {
	err = s.fs.RLock()
	if err != nil {
		s.log.WithError(err).Debug("failed to lock store for reading")
		return err
	}
	defer func() {
		err2 := s.fs.RUnlock()
		if err2 != nil {
			s.log.WithError(err2).Debug("failed to unlock store")
			if err == nil {
				err = err2
			}
		}
	}()

	err = s.pullRingUpdates(ring)
	if err != nil {
		return err
	}

	return nil
}

func (s *KeyStore) writeKeyRing(ring *KeyRing) (err error) {
	err = s.fs.Lock()
	if err != nil {
		s.log.WithError(err).Debug("failed to lock store for writing")
		return err
	}
	defer func() {
		err2 := s.fs.Unlock()
		if err2 != nil {
			s.log.WithError(err2).Debug("failed to unlock store")
			if err == nil {
				err = err2
			}
		}
	}()

	err = s.pullRingUpdates(ring)
	if err != nil {
		return err
	}

	err = ring.applyPendingTX()
	if err != nil {
		return err
	}

	err = s.pushNewRingState(ring)
	if err != nil {
		return err
	}

	ring.commitTX()
	return nil
}

func (s *KeyStore) openKeyRing(ring *KeyRing) (err error) {
	err = s.fs.Lock()
	if err != nil {
		s.log.WithError(err).Debug("failed to lock store for writing")
		return err
	}
	defer func() {
		err2 := s.fs.Unlock()
		if err2 != nil {
			s.log.WithError(err2).Debug("failed to unlock store")
			if err == nil {
				err = err2
			}
		}
	}()

	err = s.pullRingUpdates(ring)
	if err != nil {
		// If we tried to pull non-existent key ring, create a new empty one instead.
		if err == backend.ErrNotExist {
			return s.pushNewRingState(ring)
		}
		return err
	}
	return nil
}

func (s *KeyStore) pullRingUpdates(ring *KeyRing) error {
	log := s.log.WithField("path", ring.path)
	data, err := s.fetchASNring(ring.path)
	if err != nil {
		log.WithError(err).Debug("failed to fetch ring data")
		return err
	}
	// TODO: use signatures to verify directory
	asnData, _, err := s.verifyKeyRing(data, ring.path)
	if err != nil {
		log.WithError(err).Warn("failed to verify ring data")
		return err
	}
	err = ring.loadASN1(asnData)
	if err != nil {
		log.WithError(err).Debug("failed to load ring data")
		return err
	}
	return nil
}

func (s *KeyStore) pushNewRingState(ring *KeyRing) error {
	log := s.log.WithField("path", ring.path)
	// TODO: update directory signatures
	data, _, err := s.signKeyRing(ring.data, ring.path)
	if err != nil {
		log.WithError(err).Warn("failed to sign ring data")
		return err
	}
	err = s.pushASNring(data, ring.path)
	if err != nil {
		log.WithError(err).Debug("failed to push ring data")
		return err
	}
	return nil
}

const (
	keyringSuffix = ".keyring"
	newSuffix     = ".new"
)

func (s *KeyStore) fetchASNring(path string) ([]byte, error) {
	return s.fs.Get(path + keyringSuffix)
}

func (s *KeyStore) pushASNring(data []byte, path string) (err error) {
	// We do updates in this convoluted way in order to avoid data loss.
	// At every point in time we preserve original data and are able to recover
	// (assuming the underlying filesystem does not get corrupted).
	// TODO: transactional update of directories, this will be harder
	curPath := path + keyringSuffix
	newPath := path + keyringSuffix + newSuffix
	err = s.fs.Put(newPath, data)
	if err != nil {
		return err
	}
	err = s.fs.Rename(newPath, curPath)
	if err != nil {
		return err
	}
	return nil
}
