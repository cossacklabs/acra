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
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
)

// TestKeyRing runs KeyRing test suite.
func TestKeyRing(t *testing.T, newKeyStore NewKeyStore) {
	t.Run("TestKeyRingInitialState", func(t *testing.T) {
		testKeyRingInitialState(t, newKeyStore)
	})
	t.Run("TestKeyRingAddingKeys", func(t *testing.T) {
		testKeyRingAddingKeys(t, newKeyStore)
	})
	t.Run("TestKeyRingCurrent", func(t *testing.T) {
		testKeyRingCurrent(t, newKeyStore)
	})
}

func testKeyRingInitialState(t *testing.T, newKeyStore NewKeyStore) {
	store := newKeyStore(t)
	defer store.Close()

	ring, err := store.OpenKeyRingRW("my/precious/keyring")
	if err != nil {
		t.Fatalf("failed to create key ring: %v", err)
	}

	keys, err := ring.AllKeys()
	if err != nil {
		t.Errorf("failed to get all keys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("key list is not empty initially: %d elements", len(keys))
	}

	curr, err := ring.CurrentKey()
	if err != api.ErrNoCurrentKey {
		t.Errorf("expected no current key initially: %v", err)
	}
	if curr != asn1.NoKey {
		t.Errorf("current key is not nil initially: %v", curr)
	}
}

func testKeyRingAddingKeys(t *testing.T, newKeyStore NewKeyStore) {
	store := newKeyStore(t)
	defer store.Close()

	ring, err := store.OpenKeyRingRW("my/precious/keyring")
	if err != nil {
		t.Fatalf("failed to create key ring: %v", err)
	}

	keyV1, err := ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("data v1"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add key 1: %v", err)
	}
	keyV2, err := ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("data v2"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add key 2: %v", err)
	}
	keys, err := ring.AllKeys()
	if err != nil {
		t.Fatalf("failed to get all keys: %v", err)
	}

	if len(keys) != 2 && keys[0] != keyV1 && keys[1] != keyV2 {
		t.Errorf("incorrect key ordering: %v", keys)
	}
}

func testKeyRingCurrent(t *testing.T, newKeyStore NewKeyStore) {
	store := newKeyStore(t)
	defer store.Close()

	ring, err := store.OpenKeyRingRW("my/precious/keyring")
	if err != nil {
		t.Fatalf("failed to create key ring: %v", err)
	}

	curr, err := ring.CurrentKey()
	if err != api.ErrNoCurrentKey {
		t.Errorf("incorrect error when no current key: %v", err)
	}
	if curr != asn1.NoKey {
		t.Errorf("current key must be nil initially")
	}

	keyV1, err := ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("data v1"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add key 1: %v", err)
	}

	curr, err = ring.CurrentKey()
	if err != api.ErrNoCurrentKey {
		t.Errorf("incorrect error when no current key (added key 1): %v", err)
	}
	if curr != asn1.NoKey {
		t.Errorf("current key must be still nil (added key 1)")
	}
	err = ring.SetCurrent(keyV1)
	if err != nil {
		t.Fatalf("failed to set key 1 current: %v", err)
	}
	curr, err = ring.CurrentKey()
	if err != nil {
		t.Fatalf("failed to get current key (added key 1): %v", err)
	}
	if curr != keyV1 {
		t.Errorf("current key is not key 1")
	}

	keyV2, err := ring.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("data v2"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add key 2: %v", err)
	}

	curr, err = ring.CurrentKey()
	if err != nil {
		t.Fatalf("failed to get current key (added key 2): %v", err)
	}
	if curr != keyV1 {
		t.Errorf("current key is not key 1 (added key 2)")
	}
	err = ring.SetCurrent(keyV2)
	if err != nil {
		t.Fatalf("failed to set key 2 current: %v", err)
	}
	curr, err = ring.CurrentKey()
	if err != nil {
		t.Fatalf("failed to get current key (added key 2): %v", err)
	}
	if curr != keyV2 {
		t.Errorf("current key is not key 2 (added key 2, set it current)")
	}

	err = ring.SetCurrent(keyV2)
	if err != nil {
		t.Fatalf("failed to set key 2 current (twice): %v", err)
	}
	curr, err = ring.CurrentKey()
	if err != nil {
		t.Fatalf("failed to get current key (added key 2, set it current twice): %v", err)
	}
	if curr != keyV2 {
		t.Errorf("current key is not key 2 (added key 2, set it current twice)")
	}

	err = ring.SetCurrent(keyV1)
	if err != nil {
		t.Fatalf("failed to set key 1 current (after key 2): %v", err)
	}
	curr, err = ring.CurrentKey()
	if err != nil {
		t.Fatalf("failed to get current key (reset key 1): %v", err)
	}
	if curr != keyV1 {
		t.Errorf("current key is not key 1 (reset key 1)")
	}
}
