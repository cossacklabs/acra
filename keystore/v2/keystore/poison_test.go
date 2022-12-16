/*
 * Copyright 2022, Cossack Labs Limited
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
	"bytes"
	"os"
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
)

func getKeystore(t *testing.T) (*ServerKeyStore, error) {
	testEncryptionKey := []byte("test encryptionn key")
	testSignatureKey := []byte("test signature key")

	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatal(err)
	}

	suite, err := crypto.NewSCellSuite(testEncryptionKey, testSignatureKey)
	if err != nil {
		return nil, err
	}
	keyDirectoryV2, err := filesystem.OpenDirectoryRW(keyDir, suite)
	if err != nil {
		return nil, err
	}
	return NewServerKeyStore(keyDirectoryV2), nil
}

func TestPoisonKeyGeneration(t *testing.T) {
	keyStore, err := getKeystore(t)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Poison keys don't generate on Get", func(t *testing.T) {
		_, err := keyStore.GetPoisonKeyPair()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}

		_, err = keyStore.GetPoisonSymmetricKey()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}

		_, err = keyStore.GetPoisonPrivateKeys()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}
		_, err = keyStore.GetPoisonSymmetricKeys()
		if err != keystore.ErrKeysNotFound {
			t.Fatalf("Expected ErrKeysNotFound, but got %v", err)
		}
	})

	t.Run("Poison keys can be generated", func(t *testing.T) {
		err := keyStore.GeneratePoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		err = keyStore.GeneratePoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Poison key are generated successfully", func(t *testing.T) {
		keyPair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		symKey, err := keyStore.GetPoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(symKey) != keystore.SymmetricKeyLength {
			t.Fatalf("Wrong length: expected %d, but got %d", keystore.SymmetricKeyLength, len(symKey))
		}

		privateKeys, err := keyStore.GetPoisonPrivateKeys()
		if err != nil {
			t.Fatal(err)
		}
		if len(privateKeys) != 1 {
			t.Fatalf("Wrong number of private keys: expected 1, but got %d", len(privateKeys))
		}
		if !bytes.Equal(privateKeys[0].Value, keyPair.Private.Value) {
			t.Fatal("Private keys are not equal")
		}

		symKeys, err := keyStore.GetPoisonSymmetricKeys()
		if err != nil {
			t.Fatal(err)
		}
		if len(symKeys) != 1 {
			t.Fatalf("Wrong number of symmetric keys: expected 1, but got %d", len(symKeys))
		}
		if !bytes.Equal(symKeys[0], symKey) {
			t.Fatal("Symmetric keys are not equal")
		}
	})

	t.Run("Poison keys can be rotated", func(t *testing.T) {
		// Save old keys
		oldKeyPair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		oldSymKey, err := keyStore.GetPoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		// Generate new ones
		err = keyStore.GeneratePoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		err = keyStore.GeneratePoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		// Retrieve new ones
		newKeyPair, err := keyStore.GetPoisonKeyPair()
		if err != nil {
			t.Fatal(err)
		}

		newSymKey, err := keyStore.GetPoisonSymmetricKey()
		if err != nil {
			t.Fatal(err)
		}

		privateKeys, err := keyStore.GetPoisonPrivateKeys()
		if err != nil {
			t.Fatal(err)
		}

		symKeys, err := keyStore.GetPoisonSymmetricKeys()
		if err != nil {
			t.Fatal(err)
		}

		// Compare

		if bytes.Equal(oldKeyPair.Private.Value, newKeyPair.Private.Value) {
			t.Fatal("Private keys are equal after rotation")
		}

		if bytes.Equal(oldKeyPair.Public.Value, newKeyPair.Public.Value) {
			t.Fatal("Public keys are equal after rotation")
		}

		if bytes.Equal(oldSymKey, newSymKey) {
			t.Fatal("Symmetric keys are equal after rotation")
		}

		if len(privateKeys) != 2 {
			t.Fatalf("Wrong number of private keys: expected 2, but got %d", len(privateKeys))
		}
		if len(symKeys) != 2 {
			t.Fatalf("Wrong number of symmetric keys: expected 2, but got %d", len(symKeys))
		}

		if !bytes.Equal(privateKeys[0].Value, newKeyPair.Private.Value) {
			t.Fatal("First private key should be the newest one")
		}

		if !bytes.Equal(privateKeys[1].Value, oldKeyPair.Private.Value) {
			t.Fatal("First private key should be the oldest one")
		}

		if !bytes.Equal(privateKeys[0].Value, newKeyPair.Private.Value) {
			t.Fatal("First private key should be the newest one")
		}

		if !bytes.Equal(symKeys[0], newSymKey) {
			t.Fatal("First symmetric key should be the newest one")
		}

		if !bytes.Equal(symKeys[1], oldSymKey) {
			t.Fatal("Second symmetric key should be the oldest one")
		}
	})
}
