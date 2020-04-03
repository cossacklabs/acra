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

	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
)

// Errors returned by KeyRing methods accessing key data:
var (
	ErrFormatDuplicated    = errors.New("key format used multiple times")
	ErrFormatMissing       = errors.New("key format not available")
	ErrKeyNotExist         = errors.New("no key with such seqnum")
	ErrKeyDestroyed        = errors.New("key has been destroyed")
	ErrNoKeyData           = errors.New("no key data")
	ErrInvalidFormat       = errors.New("invalid key format")
	ErrInvalidState        = errors.New("invalid state transition")
	ErrInvalidCryptoperiod = errors.New("invalid key cryptoperiod")
)

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
