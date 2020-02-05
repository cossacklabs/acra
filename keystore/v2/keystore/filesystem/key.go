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
	"fmt"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
	log "github.com/sirupsen/logrus"
)

// Key provides access to a single key in KeyRing.
type Key struct {
	ring *KeyRing
	log  *log.Entry

	seqnum int
}

//
// Construction
//

func newKey(ring *KeyRing, k api.KeyDescription) (*Key, *asn1.Key, error) {
	nextSeqnum := ring.nextSeqnum()
	key := &Key{
		ring:   ring,
		log:    ring.log,
		seqnum: nextSeqnum,
	}
	keyData := &asn1.Key{
		Seqnum:     nextSeqnum,
		State:      asn1.KeyPreActive,
		ValidSince: k.ValidSince,
		ValidUntil: k.ValidUntil,
		Data:       make([]asn1.KeyData, 0, 1),
	}
	if k.ValidSince.After(k.ValidUntil) {
		return nil, nil, api.ErrInvalidCryptoperiod
	}
	if len(k.Data) == 0 {
		return nil, nil, api.ErrNoKeyData
	}
	for _, data := range k.Data {
		err := key.addKeyData(keyData, data)
		if err != nil {
			log.WithError(err).Debug("failed to add key data")
			return nil, nil, err
		}
	}
	return key, keyData, nil
}

func (k *Key) keyData() *asn1.Key {
	return k.ring.keyDataBySeqnum(k.seqnum)
}

func (k *Key) keyDataByFormat(format api.KeyFormat) *asn1.KeyData {
	key := k.keyData()
	if key == nil {
		return nil
	}
	for i := range key.Data {
		if api.KeyFormat(key.Data[i].Format) == format {
			return &key.Data[i]
		}
	}
	return nil
}

//
// Key & MutableKey interface
//

// Seqnum returns sequential number of this key in the key ring.
func (k *Key) Seqnum() (int, error) {
	return k.seqnum, nil
}

// State of the key right now.
func (k *Key) State() (api.KeyState, error) {
	key := k.keyData()
	if key == nil {
		return api.KeyDestroyed, api.ErrKeyNotExist
	}
	return api.KeyState(key.State), nil
}

// SetState changes key State to the given one, if allowed.
func (k *Key) SetState(newState api.KeyState) error {
	key := k.keyData()
	if key == nil {
		return api.ErrKeyNotExist
	}
	oldState := api.KeyState(key.State)
	log := k.log.WithField("oldState", oldState).WithField("newState", newState)

	if !api.KeyStateTransitionValid(oldState, newState) {
		log.Debug("invalid state transition requested")
		return api.ErrInvalidState
	}

	err := k.ring.changeKeyState(k.seqnum, oldState, newState)
	if err != nil {
		log.WithError(err).Debug("failed to change key state")
		return err
	}
	log.Trace("changed key state")
	return nil
}

// SetCurrent makes this key current in its key ring.
func (k *Key) SetCurrent() error {
	err := k.ring.setCurrent(k.seqnum)
	if err != nil {
		k.log.WithError(err).Debug("failed to set key current")
		return err
	}
	k.log.Trace("set key current")
	return nil
}

// ValidSince returns the time before which the key cannot be used.
func (k *Key) ValidSince() (time.Time, error) {
	key := k.keyData()
	if key == nil {
		return time.Time{}, api.ErrKeyNotExist
	}
	return key.ValidSince, nil
}

// ValidUntil returns the time since which the key should not be used.
func (k *Key) ValidUntil() (time.Time, error) {
	key := k.keyData()
	if key == nil {
		return time.Time{}, api.ErrKeyNotExist
	}
	return key.ValidUntil, nil
}

// Formats available for this key.
func (k *Key) Formats() ([]api.KeyFormat, error) {
	key := k.keyData()
	if key == nil {
		return nil, api.ErrKeyNotExist
	}
	formats := make([]api.KeyFormat, 0, len(key.Data))
	for _, data := range key.Data {
		formats = append(formats, api.KeyFormat(data.Format))
	}
	return formats, nil
}

// PublicKey data in given format, if available.
func (k *Key) PublicKey(format api.KeyFormat) ([]byte, error) {
	data := k.keyDataByFormat(format)
	if data == nil {
		return nil, api.ErrFormatMissing
	}
	key := data.PublicKey
	if len(key) == 0 {
		return nil, api.ErrInvalidFormat
	}
	return key, nil
}

// PrivateKey data in given format, if available.
func (k *Key) PrivateKey(format api.KeyFormat) ([]byte, error) {
	data := k.keyDataByFormat(format)
	if data == nil {
		return nil, api.ErrFormatMissing
	}
	if len(data.PrivateKey) == 0 {
		return nil, api.ErrInvalidFormat
	}
	decryptedKey, err := k.decryptPrivateKey(data.PrivateKey)
	if err != nil {
		k.log.WithError(err).Warn("failed to decrypt private key")
		return nil, err
	}
	return decryptedKey, nil
}

// SymmetricKey data in given format, if available.
func (k *Key) SymmetricKey(format api.KeyFormat) ([]byte, error) {
	data := k.keyDataByFormat(format)
	if data == nil {
		return nil, api.ErrFormatMissing
	}
	if len(data.SymmetricKey) == 0 {
		return nil, api.ErrInvalidFormat
	}
	decryptedKey, err := k.decryptSymmetricKey(data.SymmetricKey)
	if err != nil {
		k.log.WithError(err).Warn("failed to decrypt symmetric key")
		return nil, err
	}
	return decryptedKey, nil
}

//
// Key data encryption
//

func (k *Key) privateKeyContext() []byte {
	return []byte(fmt.Sprintf("private key %d", k.seqnum))
}

func (k *Key) encryptPrivateKey(data []byte) ([]byte, error) {
	return k.ring.encrypt(data, k.privateKeyContext())
}

func (k *Key) decryptPrivateKey(data []byte) ([]byte, error) {
	return k.ring.decrypt(data, k.privateKeyContext())
}

func (k *Key) symmetricKeyContext() []byte {
	return []byte(fmt.Sprintf("symmetric key %d", k.seqnum))
}

func (k *Key) encryptSymmetricKey(data []byte) ([]byte, error) {
	return k.ring.encrypt(data, k.symmetricKeyContext())
}

func (k *Key) decryptSymmetricKey(data []byte) ([]byte, error) {
	return k.ring.decrypt(data, k.symmetricKeyContext())
}

//
// Internal utilities
//

func (k *Key) addKeyData(keyData *asn1.Key, data api.KeyData) error {
	newData := asn1.KeyData{
		Format: asn1.KeyFormat(data.Format),
	}
	for _, data := range keyData.Data {
		if data.Format == newData.Format {
			return api.ErrFormatDuplicated
		}
	}
	switch data.Format {
	case api.ThemisPublicKeyFormat:
		if len(data.PublicKey) == 0 {
			return api.ErrNoKeyData
		}
		newData.PublicKey = data.PublicKey

	case api.ThemisKeyPairFormat:
		if len(data.PublicKey) == 0 || len(data.PrivateKey) == 0 {
			return api.ErrNoKeyData
		}
		encryptedPrivateKey, err := k.encryptPrivateKey(data.PrivateKey)
		if err != nil {
			log.WithError(err).Warn("failed to encrypt private key")
			return err
		}
		newData.PublicKey = data.PublicKey
		newData.PrivateKey = encryptedPrivateKey

	case api.ThemisSymmetricKeyFormat:
		if len(data.SymmetricKey) == 0 {
			return api.ErrNoKeyData
		}
		encryptedSymmetricKey, err := k.encryptSymmetricKey(data.SymmetricKey)
		if err != nil {
			log.WithError(err).Warn("failed to encrypt symmetric key")
			return err
		}
		newData.SymmetricKey = encryptedSymmetricKey

	default:
		return api.ErrInvalidFormat
	}
	keyData.Data = append(keyData.Data, newData)
	return nil
}
