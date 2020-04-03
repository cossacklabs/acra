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

package api

import (
	"errors"
	"time"
)

// Errors returned by KeyRing methods:
var (
	ErrNoCurrentKey = errors.New("key ring has no current key")
)

// KeyRing is a bunch of keys, with currently active one.
type KeyRing interface {
	// CurrentKey returns the key that you should currently use.
	CurrentKey() (int, error)

	// AllKeys returns all keys in the key ring, from newest to oldest.
	AllKeys() ([]int, error)

	// State of the key right now.
	State(seqnum int) (KeyState, error)

	// ValidSince returns the time before which the key cannot be used.
	ValidSince(seqnum int) (time.Time, error)
	// ValidUntil returns the time since which the key should not be used.
	ValidUntil(seqnum int) (time.Time, error)

	// Formats available for this key.
	Formats(seqnum int) ([]KeyFormat, error)
	// PublicKey data in given format, if available.
	PublicKey(seqnum int, format KeyFormat) ([]byte, error)
	// PrivateKey data in given format, if available.
	PrivateKey(seqnum int, format KeyFormat) ([]byte, error)
	// SymmetricKey data in given format, if available.
	SymmetricKey(seqnum int, format KeyFormat) ([]byte, error)
}

// MutableKeyRing is a bunch of keys, with currently active one.
// This interface allow to add new keys, update existing ones, and change the current key.
type MutableKeyRing interface {
	KeyRing

	// AddKey attaches a new key to the ring.
	AddKey(key KeyDescription) (int, error)

	// SetState changes key State to the given one, if allowed.
	SetState(seqnum int, newState KeyState) error

	// DestroyKey erases key data (but keeps the key in the ring).
	DestroyKey(seqnum int) error

	// SetCurrent makes this key current in its key ring.
	// Does nothing if the key is already current.
	SetCurrent(seqnum int) error
}

// KeyDescription describes a newly added key.
// A key can have multiple representations of attached data, but must have at least one.
type KeyDescription struct {
	ValidSince time.Time
	ValidUntil time.Time
	Data       []KeyData
}

// KeyData contains plaintext key data to be added to key store.
// Only relevant fields are stored. They must be filled according to the format.
type KeyData struct {
	Format       KeyFormat
	PublicKey    []byte
	PrivateKey   []byte
	SymmetricKey []byte
}
