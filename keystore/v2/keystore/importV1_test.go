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

package keystore

import (
	"crypto/subtle"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	keystoreV1 "github.com/cossacklabs/acra/keystore"
	filesystemV1 "github.com/cossacklabs/acra/keystore/filesystem"
	cryptoV2 "github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/themis/gothemis/keys"
)

var (
	testMasterKey     = []byte("test master key")
	testEncryptionKey = []byte("test encryptionn key")
	testSignatureKey  = []byte("test signature key")
)

func equalPrivateKeys(a, b *keys.PrivateKey) bool {
	return subtle.ConstantTimeCompare(a.Value, b.Value) == 1
}

func equalPublicKeys(a, b *keys.PublicKey) bool {
	return subtle.ConstantTimeCompare(a.Value, b.Value) == 1
}

func TestImportKeyStoreV1(t *testing.T) {
	// Prepare root keystore directory (for both versions)
	rootDirectory, err := ioutil.TempDir(os.TempDir(), "import_test")
	if err != nil {
		t.Fatalf("failed to create key directory: %v", err)
	}
	defer os.RemoveAll(rootDirectory)
	keyDirV1 := filepath.Join(rootDirectory, "v1")
	keyDirV2 := filepath.Join(rootDirectory, "v2")

	// Prepare keystore v1
	encryptor, err := keystoreV1.NewSCellKeyEncryptor(testMasterKey)
	if err != nil {
		t.Fatalf("failed to initialize encryptor: %v", err)
	}
	keyStoreV1, err := filesystemV1.NewFilesystemKeyStore(keyDirV1, encryptor)
	if err != nil {
		t.Fatalf("failed to initialize keystore v1: %v", err)
	}

	clientID := []byte("Tweedledee and Tweedledum")

	// Prepare keystore v2
	suite, err := cryptoV2.NewSCellSuite(testEncryptionKey, testSignatureKey)
	if err != nil {
		t.Fatalf("failed to initialize cryptosuite: %v", err)
	}
	keyDirectoryV2, err := filesystemV2.OpenDirectoryRW(keyDirV2, suite)
	if err != nil {
		t.Fatalf("failed to initialize keystore v2: %v", err)
	}
	keyStoreV2 := NewServerKeyStore(keyDirectoryV2)
	// Prepare various keys for testing.
	err = keyStoreV1.GenerateDataEncryptionKeys(clientID)
	if err != nil {
		t.Errorf("GenerateDataEncryptionKeys() failed: %v", err)
	}
	storagePublicKeyV1, err := keyStoreV1.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		t.Errorf("GetClientIDEncryptionPublicKey() failed: %v", err)
	}
	storagePrivateKeyV1, err := keyStoreV1.GetServerDecryptionPrivateKey(clientID)
	if err != nil {
		t.Errorf("GetServerDecryptionPrivateKey() failed: %v", err)
	}

	if err = keyStoreV1.GeneratePoisonKeyPair(); err != nil {
		t.Errorf("GeneratePoisonKeyPair() failed: %v", err)
	}

	poisonKeyPairV1, err := keyStoreV1.GetPoisonKeyPair()
	if err != nil {
		t.Errorf("GetPoisonKeyPair() failed: %v", err)
	}

	// Test setup complete, now we transfer the keys.
	exportedKeys, err := filesystemV1.EnumerateExportedKeys(keyStoreV1)
	if err != nil {
		t.Fatalf("EnumerateExportedKeys() failed: %v", err)
	}
	for i, key := range exportedKeys {
		err = keyStoreV2.ImportKeyFileV1(keyStoreV1, key)
		if err != nil {
			t.Fatalf("ImportKeyFileV1[%d] failed: %v", i, err)
		}
	}

	poisonKeyPairV2, err := keyStoreV2.GetPoisonKeyPair()
	if err != nil {
		t.Errorf("GetPoisonKeyPair() failed: %v", err)
	}
	if !equalKeyPairs(poisonKeyPairV1, poisonKeyPairV2) {
		t.Errorf("poison record key pair corrupted")
	}
	// Storage keys are easier to comprehend.
	storagePublicKeyV2, err := keyStoreV2.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		t.Errorf("GetClientIDEncryptionPublicKey() failed: %v", err)
	}
	storagePrivateKeyV2, err := keyStoreV2.GetServerDecryptionPrivateKey(clientID)
	if err != nil {
		t.Errorf("GetServerDecryptionPrivateKey() failed: %v", err)
	}
	if !equalPublicKeys(storagePublicKeyV1, storagePublicKeyV2) {
		t.Errorf("client storage public key corrupted")
	}
	if !equalPrivateKeys(storagePrivateKeyV1, storagePrivateKeyV2) {
		t.Errorf("client storage private key corrupted")
	}
}

func equalKeyPairs(a, b *keys.Keypair) bool {
	if a != nil && b != nil {
		return equalPublicKeys(a.Public, b.Public) && equalPrivateKeys(a.Private, b.Private)
	}
	return a == nil && b == nil
}
