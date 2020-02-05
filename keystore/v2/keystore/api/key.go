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
	"fmt"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
)

// Errors returned by Key methods:
var (
	ErrFormatDuplicated    = errors.New("KeyStore: key format used multiple times")
	ErrFormatMissing       = errors.New("KeyStore: key format not available")
	ErrKeyNotExist         = errors.New("KeyStore: no key with such seqnum")
	ErrNoKeyData           = errors.New("KeyStore: no key data")
	ErrInvalidFormat       = errors.New("KeyStore: invalid key format")
	ErrInvalidState        = errors.New("KeyStore: invalid state transition")
	ErrInvalidCryptoperiod = errors.New("KeyStore: invalid key cryptoperiod")
)

// Key in a KeyRing.
type Key interface {
	// Seqnum returns sequential number of this key in the key ring.
	Seqnum() (int, error)
	// State of the key right now.
	State() (KeyState, error)

	// ValidSince returns the time before which the key cannot be used.
	ValidSince() (time.Time, error)
	// ValidUntil returns the time since which the key should not be used.
	ValidUntil() (time.Time, error)

	// Formats available for this key.
	Formats() ([]KeyFormat, error)
	// PublicKey data in given format, if available.
	PublicKey(format KeyFormat) ([]byte, error)
	// PrivateKey data in given format, if available.
	PrivateKey(format KeyFormat) ([]byte, error)
	// SymmetricKey data in given format, if available.
	SymmetricKey(format KeyFormat) ([]byte, error)
}

// MutableKey in a KeyRing.
type MutableKey interface {
	Key

	// SetState changes key State to the given one, if allowed.
	SetState(newState KeyState) error

	// SetCurrent makes this key current in its key ring.
	// Does nothing if the key is already current.
	SetCurrent() error
}

// KeyFormat describes key material format.
type KeyFormat int

// Supported key material formats:
const (
	ThemisPublicKeyFormat    = KeyFormat(asn1.ThemisPublicKeyFormat)
	ThemisKeyPairFormat      = KeyFormat(asn1.ThemisKeyPairFormat)
	ThemisSymmetricKeyFormat = KeyFormat(asn1.ThemisSymmetricKeyFormat)
)

// KeyState describes current state of a key or a key pair.
type KeyState int

// Possible KeyState values:
const (
	KeyPreActive   = KeyState(asn1.KeyPreActive)
	KeyActive      = KeyState(asn1.KeyActive)
	KeySuspended   = KeyState(asn1.KeySuspended)
	KeyDeactivated = KeyState(asn1.KeyDeactivated)
	KeyCompromised = KeyState(asn1.KeyCompromised)
	KeyDestroyed   = KeyState(asn1.KeyDestroyed)
)

// String returns human-readable name of the state.
func (s KeyState) String() string {
	switch s {
	case KeyPreActive:
		return "pre-active"
	case KeyActive:
		return "active"
	case KeySuspended:
		return "suspended"
	case KeyDeactivated:
		return "deactivated"
	case KeyCompromised:
		return "compromised"
	case KeyDestroyed:
		return "destroyed"
	default:
		return fmt.Sprintf("unknown state: %d", s)
	}
}

// KeyStateTransitionValid checks a key state change.
func KeyStateTransitionValid(oldState, newState KeyState) bool {
	switch oldState {
	case KeyPreActive:
		switch newState {
		case KeyActive, KeyDeactivated, KeyCompromised, KeyDestroyed:
			return true
		}
	case KeyActive:
		switch newState {
		case KeySuspended, KeyDeactivated, KeyCompromised:
			return true
		}
	case KeySuspended:
		switch newState {
		case KeyActive, KeyDeactivated, KeyCompromised:
			return true
		}
	case KeyDeactivated:
		switch newState {
		case KeyCompromised, KeyDestroyed:
			return true
		}
	case KeyCompromised:
		switch newState {
		case KeyDestroyed:
			return true
		}
	}
	return false
}
