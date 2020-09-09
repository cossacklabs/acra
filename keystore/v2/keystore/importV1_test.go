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
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	connectorMode "github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
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
	keyStoreV2connectorServer := NewConnectorKeyStore(keyDirectoryV2, clientID, connectorMode.AcraServerMode)
	keyStoreV2connectorTranslator := NewConnectorKeyStore(keyDirectoryV2, clientID, connectorMode.AcraTranslatorMode)
	keyStoreV2translator := NewTranslatorKeyStore(keyDirectoryV2)

	// Prepare various keys for testing.
	err = keyStoreV1.GenerateDataEncryptionKeys(clientID)
	if err != nil {
		t.Errorf("GetZonePublicKey() failed: %v", err)
	}
	storagePublicKeyV1, err := keyStoreV1.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		t.Errorf("GetClientIDEncryptionPublicKey() failed: %v", err)
	}
	storagePrivateKeyV1, err := keyStoreV1.GetServerDecryptionPrivateKey(clientID)
	if err != nil {
		t.Errorf("GetServerDecryptionPrivateKey() failed: %v", err)
	}
	zoneID, _, err := keyStoreV1.GenerateZoneKey()
	if err != nil {
		t.Errorf("GenerateZoneKey() failed: %v", err)
	}
	zonePublicKeyV1, err := keyStoreV1.GetZonePublicKey(zoneID)
	if err != nil {
		t.Errorf("GetZonePublicKey() failed: %v", err)
	}
	zonePrivateKeyV1, err := keyStoreV1.GetZonePrivateKey(zoneID)
	if err != nil {
		t.Errorf("GetZonePrivateKey() failed: %v", err)
	}
	// Since we cannot access all generated key pairs via AcraServer keystore,
	// we generate them here and use Save... API
	connectorKeyPairV1, _ := keys.New(keys.TypeEC)
	err = keyStoreV1.SaveConnectorKeypair(clientID, connectorKeyPairV1)
	if err != nil {
		t.Errorf("SaveConnectorKeypair() failed: %v", err)
	}
	serverKeyPairV1, _ := keys.New(keys.TypeEC)
	err = keyStoreV1.SaveServerKeypair(clientID, serverKeyPairV1)
	if err != nil {
		t.Errorf("SaveServerKeypair() failed: %v", err)
	}
	translatorKeyPairV1, _ := keys.New(keys.TypeEC)
	err = keyStoreV1.SaveTranslatorKeypair(clientID, translatorKeyPairV1)
	if err != nil {
		t.Errorf("SaveTranslatorKeypair() failed: %v", err)
	}
	// And some finishing touches...
	authenticationKeyV1, err := keyStoreV1.GetAuthKey(true)
	if err != nil {
		t.Errorf("GetAuthKey() failed: %v", err)
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

	// Now, if this has been successful, verify keystore v2 contents.
	authenticationKeyV2, err := keyStoreV2.GetAuthKey(false)
	if err != nil {
		t.Errorf("GetAuthKey() failed: %v", err)
	}
	if !bytes.Equal(authenticationKeyV1, authenticationKeyV2) {
		t.Errorf("authentication key corrupted")
	}
	poisonKeyPairV2, err := keyStoreV2.GetPoisonKeyPair()
	if err != nil {
		t.Errorf("GetPoisonKeyPair() failed: %v", err)
	}
	if !equalKeyPairs(poisonKeyPairV1, poisonKeyPairV2) {
		t.Errorf("poison record key pair corrupted")
	}
	// Pay close attention here, transport keys are a bit complicated.
	// They cannot be all accessed via server keystore alone.
	serverPeerPublicKeyV2, err := keyStoreV2.GetPeerPublicKey(clientID)
	if err != nil {
		t.Errorf("GetPeerPublicKey() failed: %v", err)
	}
	serverPrivateKeyV2, err := keyStoreV2.GetPrivateKey(clientID)
	if err != nil {
		t.Errorf("GetPrivateKey() failed: %v", err)
	}
	if !equalPublicKeys(connectorKeyPairV1.Public, serverPeerPublicKeyV2) {
		t.Errorf("server peer public key corrupted")
	}
	if !equalPrivateKeys(serverKeyPairV1.Private, serverPrivateKeyV2) {
		t.Errorf("server private key corrupted")
	}
	connectorServerPeerPublicKeyV2, err := keyStoreV2connectorServer.GetPeerPublicKey(clientID)
	if err != nil {
		t.Errorf("GetPeerPublicKey() failed: %v", err)
	}
	connectorServerPrivateKeyV2, err := keyStoreV2connectorServer.GetPrivateKey(clientID)
	if err != nil {
		t.Errorf("GetPrivateKey() failed: %v", err)
	}
	if !equalPublicKeys(serverKeyPairV1.Public, connectorServerPeerPublicKeyV2) {
		t.Errorf("server peer public key corrupted")
	}
	if !equalPrivateKeys(connectorKeyPairV1.Private, connectorServerPrivateKeyV2) {
		t.Errorf("server private key corrupted")
	}
	connectorTranslatorPeerPublicKeyV2, err := keyStoreV2connectorTranslator.GetPeerPublicKey(clientID)
	if err != nil {
		t.Errorf("GetPeerPublicKey() failed: %v", err)
	}
	connectorTranslatorPrivateKeyV2, err := keyStoreV2connectorTranslator.GetPrivateKey(clientID)
	if err != nil {
		t.Errorf("GetPrivateKey() failed: %v", err)
	}
	if !equalPublicKeys(translatorKeyPairV1.Public, connectorTranslatorPeerPublicKeyV2) {
		t.Errorf("server peer public key corrupted")
	}
	if !equalPrivateKeys(connectorKeyPairV1.Private, connectorTranslatorPrivateKeyV2) {
		t.Errorf("server private key corrupted")
	}
	translatorPeerPublicKeyV2, err := keyStoreV2translator.GetPeerPublicKey(clientID)
	if err != nil {
		t.Errorf("GetPeerPublicKey() failed: %v", err)
	}
	translatorPrivateKeyV2, err := keyStoreV2translator.GetPrivateKey(clientID)
	if err != nil {
		t.Errorf("GetPrivateKey() failed: %v", err)
	}
	if !equalPublicKeys(connectorKeyPairV1.Public, translatorPeerPublicKeyV2) {
		t.Errorf("server peer public key corrupted")
	}
	if !equalPrivateKeys(translatorKeyPairV1.Private, translatorPrivateKeyV2) {
		t.Errorf("server private key corrupted")
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
	zonePublicKeyV2, err := keyStoreV2.GetZonePublicKey(zoneID)
	if err != nil {
		t.Errorf("GetZonePublicKey() failed: %v", err)
	}
	zonePrivateKeyV2, err := keyStoreV2.GetZonePrivateKey(zoneID)
	if err != nil {
		t.Errorf("GetZonePrivateKey() failed: %v", err)
	}
	if !equalPublicKeys(zonePublicKeyV1, zonePublicKeyV2) {
		t.Errorf("zone storage public key corrupted")
	}
	if !equalPrivateKeys(zonePrivateKeyV1, zonePrivateKeyV2) {
		t.Errorf("zone storage private key corrupted")
	}
}

func equalKeyPairs(a, b *keys.Keypair) bool {
	if a != nil && b != nil {
		return equalPublicKeys(a.Public, b.Public) && equalPrivateKeys(a.Private, b.Private)
	}
	return a == nil && b == nil
}

func equalPublicKeys(a, b *keys.PublicKey) bool {
	if a != nil && b != nil {
		return bytes.Equal(a.Value, b.Value)
	}
	return a == nil && b == nil
}

func equalPrivateKeys(a, b *keys.PrivateKey) bool {
	if a != nil && b != nil {
		return bytes.Equal(a.Value, b.Value)
	}
	return a == nil && b == nil
}
