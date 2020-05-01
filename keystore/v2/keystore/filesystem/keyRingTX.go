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
)

// keyRingTX is a transaction acting on KeyRing.
// It can be applied and rolled back.
type keyRingTX interface {
	Apply(ring *KeyRing) error
	Rollback(ring *KeyRing) error
}

// Errors returned by transactions:
var (
	errTxConcurrentModification = errors.New("concurrent key store modification")
	errTxOOORollback            = errors.New("out-of-order key store rollback")
	errTxKeyNotFound            = errors.New("no key with such seqnum in key ring")
	errTxKeyExists              = errors.New("duplicate key with seqnum in key ring")
)

type txSetKeyCurrent struct {
	oldSeqnum, newSeqnum int
}

func (tx *txSetKeyCurrent) Apply(ring *KeyRing) error {
	if ring.data.Current != tx.oldSeqnum {
		return errTxConcurrentModification
	}
	if tx.oldSeqnum != asn1.NoKey {
		oldKey, _ := ring.data.KeyWithSeqnum(tx.oldSeqnum)
		if oldKey == nil {
			return errTxKeyNotFound
		}
	}
	newKey, _ := ring.data.KeyWithSeqnum(tx.newSeqnum)
	if newKey == nil {
		return errTxKeyNotFound
	}
	ring.data.Current = tx.newSeqnum
	return nil
}

func (tx *txSetKeyCurrent) Rollback(ring *KeyRing) error {
	newKey, _ := ring.data.KeyWithSeqnum(tx.newSeqnum)
	if newKey == nil {
		return errTxKeyNotFound
	}
	if ring.data.Current != tx.newSeqnum {
		return errTxOOORollback
	}
	if tx.oldSeqnum != asn1.NoKey {
		oldKey, _ := ring.data.KeyWithSeqnum(tx.oldSeqnum)
		if oldKey == nil {
			return errTxKeyNotFound
		}
	}
	ring.data.Current = tx.oldSeqnum
	return nil
}

type txChangeKeyState struct {
	keySeqnum          int
	oldState, newState api.KeyState
}

func (tx *txChangeKeyState) Apply(ring *KeyRing) error {
	key, _ := ring.data.KeyWithSeqnum(tx.keySeqnum)
	if key == nil {
		return errTxKeyNotFound
	}
	oldState := asn1.KeyState(tx.oldState)
	newState := asn1.KeyState(tx.newState)
	if key.State != oldState {
		return errTxConcurrentModification
	}
	key.State = newState
	return nil
}

func (tx *txChangeKeyState) Rollback(ring *KeyRing) error {
	key, _ := ring.data.KeyWithSeqnum(tx.keySeqnum)
	if key == nil {
		return errTxKeyNotFound
	}
	oldState := asn1.KeyState(tx.oldState)
	newState := asn1.KeyState(tx.newState)
	if key.State != newState {
		return errTxOOORollback
	}
	key.State = oldState
	return nil
}

type txAddKey struct {
	newKey *asn1.Key
}

func (tx *txAddKey) Apply(ring *KeyRing) error {
	k, _ := ring.data.KeyWithSeqnum(tx.newKey.Seqnum)
	if k != nil {
		return errTxKeyExists
	}
	ring.data.Keys = append(ring.data.Keys, *tx.newKey)
	return nil
}

func (tx *txAddKey) Rollback(ring *KeyRing) error {
	lastKey := len(ring.data.Keys) - 1
	if len(ring.data.Keys) == 0 || ring.data.Keys[lastKey].Seqnum != tx.newKey.Seqnum {
		return errTxOOORollback
	}
	ring.data.Keys = ring.data.Keys[:lastKey]
	return nil
}

type txSetKeys struct {
	newKeys []asn1.Key
	current int

	oldKeys    []asn1.Key
	oldCurrent int
}

func (tx *txSetKeys) Apply(ring *KeyRing) error {
	tx.oldKeys = ring.data.Keys
	tx.oldCurrent = ring.data.Current
	ring.data.Keys = tx.newKeys
	ring.data.Current = tx.current
	return nil
}

func (tx *txSetKeys) Rollback(ring *KeyRing) error {
	if ring.data.Current != tx.oldCurrent {
		return errTxOOORollback
	}
	if len(ring.data.Keys) != len(tx.oldKeys) {
		return errTxOOORollback
	}
	ring.data.Keys = tx.oldKeys
	ring.data.Current = tx.oldCurrent
	return nil
}

type txDestroyKeyData struct {
	keySeqnum  int
	dataBackup []asn1.KeyData
}

func (tx *txDestroyKeyData) Apply(ring *KeyRing) error {
	key, _ := ring.data.KeyWithSeqnum(tx.keySeqnum)
	if key == nil {
		return errTxKeyNotFound
	}
	// Keep the data for possible rollback. It's encrypted so we can get away
	// with not wiping it after transaction object is destroyed.
	tx.dataBackup = key.Data
	// ASN.1 serialization requires this to be an empty slice, not nil.
	key.Data = make([]asn1.KeyData, 0)
	return nil
}

func (tx *txDestroyKeyData) Rollback(ring *KeyRing) error {
	key, _ := ring.data.KeyWithSeqnum(tx.keySeqnum)
	if key == nil || len(key.Data) != 0 {
		return errTxOOORollback
	}
	// Move the data back into the key and forget about it.
	key.Data = tx.dataBackup
	tx.dataBackup = nil
	return nil
}
