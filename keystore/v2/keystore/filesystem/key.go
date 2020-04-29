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

//
// Construction
//

func (r *KeyRing) newKey(k api.KeyDescription) (*asn1.Key, error) {
	nextSeqnum := r.nextSeqnum()
	key := &asn1.Key{
		Seqnum:     nextSeqnum,
		State:      asn1.KeyPreActive,
		ValidSince: k.ValidSince,
		ValidUntil: k.ValidUntil,
		Data:       make([]asn1.KeyData, 0, 1),
	}
	if k.ValidSince.After(k.ValidUntil) {
		return nil, api.ErrInvalidCryptoperiod
	}
	if len(k.Data) == 0 {
		return nil, api.ErrNoKeyData
	}
	for _, data := range k.Data {
		err := r.addKeyData(data, key)
		if err != nil {
			log.WithError(err).Debug("failed to add key data")
			return nil, err
		}
	}
	return key, nil
}

func (r *KeyRing) keyDataByFormat(seqnum int, format api.KeyFormat) (*asn1.KeyData, error) {
	key := r.keyDataBySeqnum(seqnum)
	if key == nil {
		return nil, api.ErrKeyNotExist
	}
	// If the key data has been destroyed then there is no point in looking for it.
	if api.KeyState(key.State) == api.KeyDestroyed {
		return nil, api.ErrKeyDestroyed
	}
	for i := range key.Data {
		if api.KeyFormat(key.Data[i].Format) == format {
			return &key.Data[i], nil
		}
	}
	return nil, api.ErrFormatMissing
}

//
// KeyAccess & MutableKeyAccess interface
//

// State of the key right now.
func (r *KeyRing) State(seqnum int) (api.KeyState, error) {
	key := r.keyDataBySeqnum(seqnum)
	if key == nil {
		return api.KeyDestroyed, api.ErrKeyNotExist
	}
	return api.KeyState(key.State), nil
}

// SetState changes key State to the given one, if allowed.
func (r *KeyRing) SetState(seqnum int, newState api.KeyState) error {
	key := r.keyDataBySeqnum(seqnum)
	if key == nil {
		return api.ErrKeyNotExist
	}
	oldState := api.KeyState(key.State)
	log := r.log.WithField("oldState", oldState).WithField("newState", newState)

	if !api.KeyStateTransitionValid(oldState, newState) {
		log.Debug("invalid state transition requested")
		return api.ErrInvalidState
	}

	err := r.changeKeyState(seqnum, oldState, newState)
	if err != nil {
		log.WithError(err).Debug("failed to change key state")
		return err
	}
	log.Trace("changed key state")
	return nil
}

// SetCurrent makes this key current in its key ring.
func (r *KeyRing) SetCurrent(seqnum int) error {
	err := r.setCurrent(seqnum)
	if err != nil {
		r.log.WithError(err).Debug("failed to set key current")
		return err
	}
	r.log.WithField("seqnum", seqnum).Trace("set key current")
	return nil
}

// DestroyKey erases key data (but keeps the key in the key ring).
func (r *KeyRing) DestroyKey(seqnum int) error {
	log := r.log.WithField("seqnum", seqnum)
	key := r.keyDataBySeqnum(seqnum)
	if key == nil {
		return api.ErrKeyNotExist
	}
	oldState := api.KeyState(key.State)

	if !api.KeyStateTransitionValid(oldState, api.KeyDestroyed) {
		log.WithField("oldState", oldState).Debug("Not allowed to destroy key")
		return api.ErrInvalidState
	}

	err := r.destroyKey(seqnum, oldState)
	if err != nil {
		log.WithError(err).Debug("Failed to destroy key")
		return err
	}
	log.Trace("Key destroyed")
	return nil
}

// ValidSince returns the time before which the key cannot be used.
func (r *KeyRing) ValidSince(seqnum int) (time.Time, error) {
	key := r.keyDataBySeqnum(seqnum)
	if key == nil {
		return time.Time{}, api.ErrKeyNotExist
	}
	return key.ValidSince, nil
}

// ValidUntil returns the time since which the key should not be used.
func (r *KeyRing) ValidUntil(seqnum int) (time.Time, error) {
	key := r.keyDataBySeqnum(seqnum)
	if key == nil {
		return time.Time{}, api.ErrKeyNotExist
	}
	return key.ValidUntil, nil
}

// Formats available for this key.
func (r *KeyRing) Formats(seqnum int) ([]api.KeyFormat, error) {
	key := r.keyDataBySeqnum(seqnum)
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
func (r *KeyRing) PublicKey(seqnum int, format api.KeyFormat) ([]byte, error) {
	data, err := r.keyDataByFormat(seqnum, format)
	if err != nil {
		return nil, err
	}
	key := data.PublicKey
	if len(key) == 0 {
		return nil, api.ErrInvalidFormat
	}
	return key, nil
}

// PrivateKey data in given format, if available.
func (r *KeyRing) PrivateKey(seqnum int, format api.KeyFormat) ([]byte, error) {
	data, err := r.keyDataByFormat(seqnum, format)
	if err != nil {
		return nil, err
	}
	if len(data.PrivateKey) == 0 {
		return nil, api.ErrNoKeyData
	}
	decryptedKey, err := r.decryptPrivateKey(seqnum, data.PrivateKey)
	if err != nil {
		r.log.WithError(err).Warn("failed to decrypt private key")
		return nil, err
	}
	return decryptedKey, nil
}

// SymmetricKey data in given format, if available.
func (r *KeyRing) SymmetricKey(seqnum int, format api.KeyFormat) ([]byte, error) {
	data, err := r.keyDataByFormat(seqnum, format)
	if err != nil {
		return nil, err
	}
	if len(data.SymmetricKey) == 0 {
		return nil, api.ErrInvalidFormat
	}
	decryptedKey, err := r.decryptSymmetricKey(seqnum, data.SymmetricKey)
	if err != nil {
		r.log.WithError(err).Warn("failed to decrypt symmetric key")
		return nil, err
	}
	return decryptedKey, nil
}

//
// Key data encryption
//

func (r *KeyRing) privateKeyContext(seqnum int) []byte {
	return []byte(fmt.Sprintf("private key %d", seqnum))
}

func (r *KeyRing) encryptPrivateKey(seqnum int, data []byte) ([]byte, error) {
	return r.encrypt(data, r.privateKeyContext(seqnum))
}

func (r *KeyRing) decryptPrivateKey(seqnum int, data []byte) ([]byte, error) {
	return r.decrypt(data, r.privateKeyContext(seqnum))
}

func (r *KeyRing) symmetricKeyContext(seqnum int) []byte {
	return []byte(fmt.Sprintf("symmetric key %d", seqnum))
}

func (r *KeyRing) encryptSymmetricKey(seqnum int, data []byte) ([]byte, error) {
	return r.encrypt(data, r.symmetricKeyContext(seqnum))
}

func (r *KeyRing) decryptSymmetricKey(seqnum int, data []byte) ([]byte, error) {
	return r.decrypt(data, r.symmetricKeyContext(seqnum))
}

//
// Internal utilities
//

func (r *KeyRing) addKeyData(data api.KeyData, key *asn1.Key) error {
	newData := asn1.KeyData{
		Format: asn1.KeyFormat(data.Format),
	}
	for _, data := range key.Data {
		if data.Format == newData.Format {
			return api.ErrFormatDuplicated
		}
	}
	switch data.Format {
	case api.ThemisKeyPairFormat:
		if len(data.PublicKey) == 0 {
			return api.ErrNoKeyData
		}
		newData.PublicKey = data.PublicKey
		if len(data.PrivateKey) != 0 {
			encryptedPrivateKey, err := r.encryptPrivateKey(key.Seqnum, data.PrivateKey)
			if err != nil {
				log.WithError(err).Warn("failed to encrypt private key")
				return err
			}
			newData.PrivateKey = encryptedPrivateKey
		}

	case api.ThemisSymmetricKeyFormat:
		if len(data.SymmetricKey) == 0 {
			return api.ErrNoKeyData
		}
		encryptedSymmetricKey, err := r.encryptSymmetricKey(key.Seqnum, data.SymmetricKey)
		if err != nil {
			log.WithError(err).Warn("failed to encrypt symmetric key")
			return err
		}
		newData.SymmetricKey = encryptedSymmetricKey

	default:
		return api.ErrInvalidFormat
	}
	key.Data = append(key.Data, newData)
	return nil
}
