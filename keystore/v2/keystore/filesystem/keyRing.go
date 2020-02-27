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
	"errors"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
	log "github.com/sirupsen/logrus"
)

// KeyRing is a KeyRing provided by KeyStore.
// It provides a snapshot of data which might be outdated.
type KeyRing struct {
	store *KeyStore
	log   *log.Entry

	// Location of this key ring in KeyStore.
	path string

	// Data stored in the key ring and views into it.
	data *asn1.KeyRing

	// Transaction log of pending modifications to the key ring.
	txLog []keyRingTX
}

//
// Construction
//

var errInvalidCurrentIndex = errors.New("KeyStore: invalid Current index in key ring")

func newKeyRing(store *KeyStore, path string) *KeyRing {
	ring := &KeyRing{
		store: store,
		log:   store.log,
		path:  path,
		data: &asn1.KeyRing{
			// TODO: shouldn't this be only the last component?..
			Purpose: asn1.LikelyUTF8String(path),
			Keys:    make([]asn1.Key, 0),
			Current: asn1.NoKey,
		},
	}
	return ring
}

func (r *KeyRing) toASN1() asn1.KeyRing {
	return *r.data
}

func (r *KeyRing) loadASN1(ring *asn1.KeyRing) error {
	r.data = ring
	return nil
}

//
// KeyRing & MutableKeyRing interface
//

// CurrentKey returns current key of this key ring, if available.
func (r *KeyRing) CurrentKey() (int, error) {
	seqnum := r.data.Current
	if seqnum == asn1.NoKey {
		return seqnum, api.ErrNoCurrentKey
	}
	return seqnum, nil
}

// AllKeys returns all keys of this key ring, from newest to oldest.
func (r *KeyRing) AllKeys() ([]int, error) {
	// Return a copy so that the caller cannot modify *our* cache. Also,
	// return keys in reverse order, from newest to oldest. This makes
	// AcraStruct decryption attempts more likely to succeed earlier.
	keyCount := len(r.data.Keys)
	keySeqnums := make([]int, keyCount)
	for i := range r.data.Keys {
		keySeqnums[keyCount-i-1] = r.data.Keys[i].Seqnum
	}
	return keySeqnums, nil
}

// AddKey appends a key to the key ring based on its description.
// Newly added key is returned if you wish to inspect or modify its state.
// Current key is not changed when a new key is added.
func (r *KeyRing) AddKey(key api.KeyDescription) (int, error) {
	newKey, err := r.newKey(key)
	if err != nil {
		r.log.WithError(err).Debug("failed to make new key")
		return asn1.NoKey, err
	}
	err = r.addKey(newKey)
	if err != nil {
		r.log.WithError(err).Debug("failed to add new key")
		return asn1.NoKey, err
	}
	r.log.Trace("new key added to key ring")
	return newKey.Seqnum, nil
}

//
// Key data encryption
//

func (r *KeyRing) keyRingContext(context []byte) []byte {
	c := make([]byte, 0, len("key ring ")+len(r.path)+len(": ")+len(context))
	c = append(c, "key ring "...)
	c = append(c, r.path...)
	c = append(c, ": "...)
	c = append(c, context...)
	return c
}

func (r *KeyRing) encrypt(data, context []byte) ([]byte, error) {
	return r.store.encrypt(data, r.keyRingContext(context))
}

func (r *KeyRing) decrypt(data, context []byte) ([]byte, error) {
	return r.store.decrypt(data, r.keyRingContext(context))
}

//
// Transaction handling
//

func (r *KeyRing) pendingUpdates() bool {
	return len(r.txLog) > 0
}

func (r *KeyRing) applyPendingTX() error {
	for lastTX, tx := range r.txLog {
		err := tx.Apply(r)
		if err != nil {
			r.log.WithError(err).Debug("failed to apply update")
			// Apply damage control. We cannot handle double faults so our best option
			// is to complain in logs and then keep calm and carry on, betting on luck.
			// Rollback should not fail, actually, but panicking is too destructive now.
			// TODO: is it possible to just snapshot the original state instead?
			for i := lastTX - 1; i >= 0; i-- {
				err := r.txLog[i].Rollback(r)
				if err != nil {
					r.log.WithError(err).Warn("failed to roll back update")
				}
			}
			return err
		}
	}
	return nil
}

func (r *KeyRing) commitTX() {
	r.txLog = nil
}

func (r *KeyRing) setCurrent(newSeqnum int) error {
	oldSeqnum := r.data.Current
	r.pushTX(&txSetKeyCurrent{oldSeqnum, newSeqnum})
	err := r.store.syncKeyRing(r)
	if err != nil {
		r.popTX()
	}
	return err
}

func (r *KeyRing) changeKeyState(keySeqnum int, oldState, newState api.KeyState) error {
	r.pushTX(&txChangeKeyState{keySeqnum, oldState, newState})
	err := r.store.syncKeyRing(r)
	if err != nil {
		r.popTX()
	}
	return err
}

func (r *KeyRing) addKey(newKey *asn1.Key) error {
	r.pushTX(&txAddKey{newKey})
	err := r.store.syncKeyRing(r)
	if err != nil {
		r.popTX()
	}
	return err
}

//
// Internal utilities
//

func (r *KeyRing) keyDataBySeqnum(seqnum int) *asn1.Key {
	key, _ := r.data.KeyWithSeqnum(seqnum)
	return key
}

// Don't start with zero to not match zero-initialized defaults.
const firstSeqnum = 1

func (r *KeyRing) nextSeqnum() int {
	if len(r.data.Keys) == 0 {
		return firstSeqnum
	}
	return r.data.Keys[len(r.data.Keys)-1].Seqnum + 1
}

func (r *KeyRing) pushTX(tx keyRingTX) {
	r.txLog = append(r.txLog, tx)
}

func (r *KeyRing) popTX() keyRingTX {
	if len(r.txLog) == 0 {
		return nil
	}
	last := len(r.txLog) - 1
	tx := r.txLog[last]
	r.txLog = r.txLog[:last]
	return tx
}
