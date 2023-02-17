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
	"crypto/rand"
	"time"

	"github.com/cossacklabs/themis/gothemis/keys"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
)

const defaultKeyCryptoperiod = 365 * 24 * time.Hour // 1 year

func (s *ServerKeyStore) currentKeyPair(ring api.KeyRing) (*keys.Keypair, error) {
	current, err := ring.CurrentKey()
	if err != nil {
		return nil, err
	}
	publicKey, err := ring.PublicKey(current, api.ThemisKeyPairFormat)
	if err != nil {
		return nil, err
	}
	privateKey, err := ring.PrivateKey(current, api.ThemisKeyPairFormat)
	if err != nil {
		return nil, err
	}
	return &keys.Keypair{
		Public:  &keys.PublicKey{Value: publicKey},
		Private: &keys.PrivateKey{Value: privateKey},
	}, nil
}

func (s *ServerKeyStore) currentPairPublicKey(ring api.KeyRing) (*keys.PublicKey, error) {
	current, err := ring.CurrentKey()
	if err != nil {
		return nil, err
	}
	publicKey, err := ring.PublicKey(current, api.ThemisKeyPairFormat)
	if err != nil {
		return nil, err
	}
	return &keys.PublicKey{Value: publicKey}, nil
}

func (s *ServerKeyStore) currentPairPrivateKey(ring api.KeyRing) (*keys.PrivateKey, error) {
	current, err := ring.CurrentKey()
	if err != nil {
		return nil, err
	}
	privateKey, err := ring.PrivateKey(current, api.ThemisKeyPairFormat)
	if err != nil {
		return nil, err
	}
	return &keys.PrivateKey{Value: privateKey}, nil
}

func (s *ServerKeyStore) allPairPrivateKeys(ring api.KeyRing) ([]*keys.PrivateKey, error) {
	seqnums, err := ring.AllKeys()
	if err != nil {
		return nil, err
	}
	privateKeys := make([]*keys.PrivateKey, len(seqnums))
	for i, seqnum := range seqnums {
		privateKey, err := ring.PrivateKey(seqnum, api.ThemisKeyPairFormat)
		if err != nil {
			return nil, err
		}
		privateKeys[i] = &keys.PrivateKey{Value: privateKey}
	}
	return privateKeys, nil
}

func (s *ServerKeyStore) newCurrentKeyPair(ring api.MutableKeyRing) (*keys.Keypair, error) {
	pair, err := keys.New(keys.TypeEC)
	if err != nil {
		return nil, err
	}
	err = s.addCurrentKeyPair(ring, pair)
	if err != nil {
		return nil, err
	}
	return pair, nil
}

func (s *ServerKeyStore) addCurrentKeyPair(ring api.MutableKeyRing, pair *keys.Keypair) error {
	i, err := ring.AddKey(s.describeNewKeyPair(pair))
	if err != nil {
		return err
	}
	err = ring.SetCurrent(i)
	if err != nil {
		return err
	}
	return nil
}

func (s *ServerKeyStore) destroyCurrentKeyPair(ring api.MutableKeyRing) error {
	current, err := ring.CurrentKey()
	if err != nil {
		return err
	}
	err = ring.DestroyKey(current)
	if err != nil {
		return err
	}
	return nil
}

func (s *ServerKeyStore) describeNewKeyPair(keypair *keys.Keypair) api.KeyDescription {
	return api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(defaultKeyCryptoperiod),
		Data: []api.KeyData{
			{
				Format:     api.ThemisKeyPairFormat,
				PublicKey:  keypair.Public.Value,
				PrivateKey: keypair.Private.Value,
			},
		},
	}
}

const symmtricKeyBytes = 32

// TODO: replace with keys.NewSymetricKey() once GoThemis 0.13 is released
func (s *ServerKeyStore) newSymmetricKey() ([]byte, error) {
	randomBytes := make([]byte, symmtricKeyBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func (s *ServerKeyStore) currentSymmetricKey(ring api.KeyRing) ([]byte, error) {
	current, err := ring.CurrentKey()
	if err != nil {
		return nil, err
	}
	key, err := ring.SymmetricKey(current, api.ThemisSymmetricKeyFormat)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *ServerKeyStore) allSymmetricKeys(ring api.KeyRing) ([][]byte, error) {
	seqnums, err := ring.AllKeys()
	if err != nil {
		return nil, err
	}
	symmetricKeys := make([][]byte, len(seqnums))
	for i, seqnum := range seqnums {
		symmetricKey, err := ring.SymmetricKey(seqnum, api.ThemisSymmetricKeyFormat)
		if err != nil {
			return nil, err
		}
		symmetricKeys[i] = symmetricKey
	}
	return symmetricKeys, nil
}

func (s *ServerKeyStore) newCurrentSymmetricKey(ring api.MutableKeyRing) ([]byte, error) {
	key, err := s.newSymmetricKey()
	if err != nil {
		return nil, err
	}
	err = s.addCurrentSymmetricKey(ring, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *ServerKeyStore) addCurrentSymmetricKey(ring api.MutableKeyRing, key []byte) error {
	i, err := ring.AddKey(s.describeNewSymmetricKey(key))
	if err != nil {
		return err
	}
	err = ring.SetCurrent(i)
	if err != nil {
		return err
	}
	return nil
}

func (s *ServerKeyStore) describeNewSymmetricKey(key []byte) api.KeyDescription {
	return api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(defaultKeyCryptoperiod),
		Data: []api.KeyData{
			{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: key,
			},
		},
	}
}

func (s *ServerKeyStore) hasCurrentKey(ring api.KeyRing) (bool, error) {
	_, err := ring.CurrentKey()
	if err == api.ErrNoCurrentKey {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
