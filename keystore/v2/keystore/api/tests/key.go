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

package tests

import (
	"bytes"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
)

// TestKey runs Key test suite.
func TestKey(t *testing.T, newKeyStore NewKeyStore) {
	t.Run("TestKeyInitialState", func(t *testing.T) {
		testKeyInitialState(t, newKeyStore)
	})
	t.Run("TestKeyFormatLookup", func(t *testing.T) {
		testKeyFormatLookup(t, newKeyStore)
	})
	t.Run("TestKeyInvalidInputs", func(t *testing.T) {
		testKeyInvalidInputs(t, newKeyStore)
	})
	t.Run("TestKeyStateSwitching", func(t *testing.T) {
		testKeyStateSwitching(t, newKeyStore)
	})
}

func testKeyInitialState(t *testing.T, newKeyStore NewKeyStore) {
	store := newKeyStore(t)
	defer store.Close()

	ring, err := store.OpenKeyRingRW("My Little Testing: Key Rings Are Magic")
	if err != nil {
		t.Fatalf("failed to create key ring: %v", err)
	}

	validSince, _ := time.Parse(time.RFC3339, "2020-02-11T13:41:00Z")
	validUntil, _ := time.Parse(time.RFC3339, "2021-02-11T13:41:00Z")
	publicKey := []byte("my public key")
	privateKey := []byte("my private key")

	key, err := ring.AddKey(api.KeyDescription{
		ValidSince: validSince,
		ValidUntil: validUntil,
		Data: []api.KeyData{
			api.KeyData{
				Format:     api.ThemisKeyPairFormat,
				PublicKey:  publicKey,
				PrivateKey: privateKey,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add key: %v", err)
	}

	keyState, err := ring.State(key)
	if err != nil {
		t.Fatalf("failed to get current state: %v", err)
	}
	if keyState != api.KeyPreActive {
		t.Errorf("incorrect initial state, actual: %v, expected: %v", keyState, api.KeyPreActive)
	}
	keyValidSince, err := ring.ValidSince(key)
	if err != nil {
		t.Fatalf("failed to get validity range: %v", err)
	}
	keyValidUntil, err := ring.ValidUntil(key)
	if err != nil {
		t.Fatalf("failed to get validity range: %v", err)
	}
	if keyValidSince != validSince || keyValidUntil != validUntil {
		t.Errorf("incorrect validity range, actual: (%v .. %v), expected: (%v .. %v)",
			keyValidSince, keyValidUntil, validSince, validUntil)
	}
	formats, err := ring.Formats(key)
	if err != nil {
		t.Fatalf("failed to get key format: %v", err)
	}
	if len(formats) != 1 && formats[0] != api.ThemisKeyPairFormat {
		t.Errorf("incorrect initial format list: %v", formats)
	}
	actualPublicKey, err := ring.PublicKey(key, api.ThemisKeyPairFormat)
	if err != nil {
		t.Errorf("failed to get public key: %v", err)
	}
	if !bytes.Equal(actualPublicKey, publicKey) {
		t.Errorf("incorrect public key value")
	}
	actualPrivateKey, err := ring.PrivateKey(key, api.ThemisKeyPairFormat)
	if err != nil {
		t.Errorf("failed to get private key: %v", err)
	}
	if !bytes.Equal(actualPrivateKey, privateKey) {
		t.Errorf("incorrect private key value")
	}
}

func testKeyFormatLookup(t *testing.T, newKeyStore NewKeyStore) {
	store := newKeyStore(t)
	defer store.Close()

	ring, err := store.OpenKeyRingRW("My Little Testing: Key Rings Are Magic")
	if err != nil {
		t.Fatalf("failed to create key ring: %v", err)
	}

	key, err := ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:     api.ThemisKeyPairFormat,
				PublicKey:  []byte("my public key"),
				PrivateKey: []byte("my private key"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add key: %v", err)
	}

	_, err = ring.PublicKey(key, api.ThemisPublicKeyFormat)
	if err != api.ErrFormatMissing {
		t.Errorf("found public key with key pair format: %v", err)
	}

	_, err = ring.SymmetricKey(key, api.ThemisSymmetricKeyFormat)
	if err != api.ErrFormatMissing {
		t.Errorf("found symmetric key with key pair format: %v", err)
	}
}

func testKeyInvalidInputs(t *testing.T, newKeyStore NewKeyStore) {
	store := newKeyStore(t)
	defer store.Close()

	ring, err := store.OpenKeyRingRW("My Little Testing: Key Rings Are Magic")
	if err != nil {
		t.Fatalf("failed to create key ring: %v", err)
	}

	_, err = ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	})
	if err != api.ErrNoKeyData {
		t.Errorf("cannot add key with no data: %v", err)
	}

	_, err = ring.AddKey(api.KeyDescription{
		ValidSince: time.Now().Add(time.Hour),
		ValidUntil: time.Now(),
	})
	if err != api.ErrInvalidCryptoperiod {
		t.Errorf("cannot add key with incorrect validity range: %v", err)
	}

	_, err = ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.KeyFormat(9000),
				SymmetricKey: []byte("secret"),
			},
		},
	})
	if err != api.ErrInvalidFormat {
		t.Errorf("cannot add key with weird format: %v", err)
	}

	_, err = ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:     api.ThemisPublicKeyFormat,
				PrivateKey: []byte("ompf"),
			},
		},
	})
	if err != api.ErrNoKeyData {
		t.Errorf("cannot add public key without data: %v", err)
	}

	_, err = ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:     api.ThemisKeyPairFormat,
				PublicKey:  []byte{},
				PrivateKey: []byte("asdasdas"),
			},
		},
	})
	if err != api.ErrNoKeyData {
		t.Errorf("cannot add key pair without full data: %v", err)
	}

	_, err = ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:     api.ThemisSymmetricKeyFormat,
				PrivateKey: []byte("should use SymmetricKey"),
			},
		},
	})
	if err != api.ErrNoKeyData {
		t.Errorf("cannot add symmetric key without data: %v", err)
	}

	_, err = ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("secret"),
			},
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("more"),
			},
		},
	})
	if err != api.ErrFormatDuplicated {
		t.Errorf("cannot add the same format twice: %v", err)
	}
}

func testKeyStateSwitching(t *testing.T, newKeyStore NewKeyStore) {
	store := newKeyStore(t)
	defer store.Close()

	ring, err := store.OpenKeyRingRW("My Little Testing: Key Rings Are Magic")
	if err != nil {
		t.Fatalf("failed to create key ring: %v", err)
	}

	key, err := ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("secret"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add key: %v", err)
	}

	checkKeyState := func(ring api.KeyRing, key int, expected api.KeyState) {
		actual, err := ring.State(key)
		if err != nil {
			t.Fatalf("failed to get current state: %v", err)
		}
		if actual != expected {
			t.Errorf("incorrect key state, actual: %v, expected: %v", actual, expected)
		}
	}

	checkKeyState(ring, key, api.KeyPreActive)

	err = ring.SetState(key, api.KeyActive)
	if err != nil {
		t.Fatalf("failed to switch state to active: %v", err)
	}
	checkKeyState(ring, key, api.KeyActive)

	err = ring.SetState(key, api.KeySuspended)
	if err != nil {
		t.Fatalf("failed to switch state to suspended: %v", err)
	}
	checkKeyState(ring, key, api.KeySuspended)

	err = ring.SetState(key, api.KeyActive)
	if err != nil {
		t.Fatalf("failed to switch state to active: %v", err)
	}
	checkKeyState(ring, key, api.KeyActive)

	err = ring.SetState(key, api.KeyPreActive)
	if err != api.ErrInvalidState {
		t.Fatalf("cannot switch state back to pre-active: %v", err)
	}
	checkKeyState(ring, key, api.KeyActive)

	err = ring.SetState(key, api.KeyDeactivated)
	if err != nil {
		t.Fatalf("failed to switch state to deactivated: %v", err)
	}
	checkKeyState(ring, key, api.KeyDeactivated)

	err = ring.SetState(key, api.KeyActive)
	if err != api.ErrInvalidState {
		t.Fatalf("cannot switch state back to active: %v", err)
	}
	checkKeyState(ring, key, api.KeyDeactivated)

	err = ring.SetState(key, api.KeyCompromised)
	if err != nil {
		t.Fatalf("failed to switch state to compromised: %v", err)
	}
	checkKeyState(ring, key, api.KeyCompromised)

	err = ring.SetState(key, api.KeyActive)
	if err != api.ErrInvalidState {
		t.Fatalf("cannot switch state back to active (from compromise): %v", err)
	}
	checkKeyState(ring, key, api.KeyCompromised)

	err = ring.SetState(key, api.KeyDestroyed)
	if err != nil {
		t.Fatalf("failed to switch state to destroyed: %v", err)
	}
	checkKeyState(ring, key, api.KeyDestroyed)
}
