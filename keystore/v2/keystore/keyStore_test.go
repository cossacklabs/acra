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
	"testing"

	connector_mode "github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func testKeyDirectory(t *testing.T) api.MutableKeyStore {
	suite, err := crypto.NewSCellSuite(testEncryptionKey, testSignatureKey)
	if err != nil {
		t.Fatalf("Failed to initialize crypto suite: %v", err)
	}
	keyDirectory, err := filesystem.NewInMemory(suite)
	if err != nil {
		t.Fatalf("Failed to initialize in-memory keystore: %v", err)
	}
	return keyDirectory
}

var (
	testClientA = []byte("Alice")
	testClientB = []byte("Bob")
)

const (
	keyServerA     = "Server: Alice"
	keyServerB     = "Server: Bob"
	keyConnectorA  = "Connector: Alice"
	keyConnectorB  = "Connector: Bob"
	keyTranslatorA = "Translator: Alice"
	keyTranslatorB = "Translator: Bob"
)

func generateTestTransportKeys(t *testing.T, keyStore keystore.TransportKeyCreation) map[string]*keys.Keypair {
	transportKeys := make(map[string]*keys.Keypair, 6)

	serverA, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	err = keyStore.SaveServerKeypair(testClientA, serverA)
	if err != nil {
		t.Errorf("Failed to save key pair: %v", err)
	}
	transportKeys[keyServerA] = serverA

	serverB, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	err = keyStore.SaveServerKeypair(testClientB, serverB)
	if err != nil {
		t.Errorf("Failed to save key pair: %v", err)
	}
	transportKeys[keyServerB] = serverB

	connectorA, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	err = keyStore.SaveConnectorKeypair(testClientA, connectorA)
	if err != nil {
		t.Errorf("Failed to save key pair: %v", err)
	}
	transportKeys[keyConnectorA] = connectorA

	connectorB, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	err = keyStore.SaveConnectorKeypair(testClientB, connectorB)
	if err != nil {
		t.Errorf("Failed to save key pair: %v", err)
	}
	transportKeys[keyConnectorB] = connectorB

	translatorA, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	err = keyStore.SaveTranslatorKeypair(testClientA, translatorA)
	if err != nil {
		t.Errorf("Failed to save key pair: %v", err)
	}
	transportKeys[keyTranslatorA] = translatorA

	translatorB, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	err = keyStore.SaveTranslatorKeypair(testClientB, translatorB)
	if err != nil {
		t.Errorf("Failed to save key pair: %v", err)
	}
	transportKeys[keyTranslatorB] = translatorB

	return transportKeys
}

func equalPrivateKeys(a, b *keys.PrivateKey) bool {
	return subtle.ConstantTimeCompare(a.Value, b.Value) == 1
}

func equalPublicKeys(a, b *keys.PublicKey) bool {
	return subtle.ConstantTimeCompare(a.Value, b.Value) == 1
}

func TestServerKeyStore(t *testing.T) {
	keyStore := NewServerKeyStore(testKeyDirectory(t))
	keys := generateTestTransportKeys(t, keyStore)

	privateA, err := keyStore.GetPrivateKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientA, err)
	}
	if !equalPrivateKeys(privateA, keys[keyServerA].Private) {
		t.Errorf("Invalid private key for %s", testClientA)
	}

	privateB, err := keyStore.GetPrivateKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientB, err)
	}
	if !equalPrivateKeys(privateB, keys[keyServerB].Private) {
		t.Errorf("Invalid private key for %s", testClientB)
	}

	// AcraServer's peer is AcraConnector. It expects AcraConnector's keys.

	publicA, err := keyStore.GetPeerPublicKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientA, err)
	}
	if !equalPublicKeys(publicA, keys[keyConnectorA].Public) {
		t.Errorf("Invalid public key for %s", testClientA)
	}

	publicB, err := keyStore.GetPeerPublicKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientB, err)
	}
	if !equalPublicKeys(publicB, keys[keyConnectorB].Public) {
		t.Errorf("Invalid public key for %s", testClientB)
	}
}

func TestConnectorKeyStoreServerMode(t *testing.T) {
	keyStore := NewConnectorKeyStore(testKeyDirectory(t), testClientA, connector_mode.AcraServerMode)
	keys := generateTestTransportKeys(t, keyStore)

	privateA, err := keyStore.GetPrivateKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientA, err)
	}
	if !equalPrivateKeys(privateA, keys[keyConnectorA].Private) {
		t.Errorf("Invalid private key for %s", testClientA)
	}

	privateB, err := keyStore.GetPrivateKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientB, err)
	}
	if !equalPrivateKeys(privateB, keys[keyConnectorB].Private) {
		t.Errorf("Invalid private key for %s", testClientB)
	}

	// AcraConnector's peer is AcraServer. It expects AcraServer's keys
	// for configured client, regardless of the argument.

	publicA, err := keyStore.GetPeerPublicKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientA, err)
	}
	if !equalPublicKeys(publicA, keys[keyServerA].Public) {
		t.Errorf("Invalid public key for %s", testClientA)
	}

	publicB, err := keyStore.GetPeerPublicKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientB, err)
	}
	// Note that we still expect the "keyServerA" public key.
	if !equalPublicKeys(publicB, keys[keyServerA].Public) {
		t.Errorf("Invalid public key for %s", testClientB)
	}
}

func TestConnectorKeyStoreTranslatorMode(t *testing.T) {
	keyStore := NewConnectorKeyStore(testKeyDirectory(t), testClientA, connector_mode.AcraTranslatorMode)
	keys := generateTestTransportKeys(t, keyStore)

	privateA, err := keyStore.GetPrivateKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientA, err)
	}
	if !equalPrivateKeys(privateA, keys[keyConnectorA].Private) {
		t.Errorf("Invalid private key for %s", testClientA)
	}

	privateB, err := keyStore.GetPrivateKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientB, err)
	}
	if !equalPrivateKeys(privateB, keys[keyConnectorB].Private) {
		t.Errorf("Invalid private key for %s", testClientB)
	}

	// AcraConnector's peer is AcraTranslator. It expects AcraTranslator's keys
	// for configured client, regardless of the argument.

	publicA, err := keyStore.GetPeerPublicKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientA, err)
	}
	if !equalPublicKeys(publicA, keys[keyTranslatorA].Public) {
		t.Errorf("Invalid public key for %s", testClientA)
	}

	publicB, err := keyStore.GetPeerPublicKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientB, err)
	}
	// Note that we still expect the "keyTranslatorA" public key.
	if !equalPublicKeys(publicB, keys[keyTranslatorA].Public) {
		t.Errorf("Invalid public key for %s", testClientB)
	}
}

func TestTranslatorKeyStore(t *testing.T) {
	keyStore := NewTranslatorKeyStore(testKeyDirectory(t))
	keys := generateTestTransportKeys(t, keyStore)

	privateA, err := keyStore.GetPrivateKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientA, err)
	}
	if !equalPrivateKeys(privateA, keys[keyTranslatorA].Private) {
		t.Errorf("Invalid private key for %s", testClientA)
	}

	privateB, err := keyStore.GetPrivateKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get private key for %s: %v", testClientB, err)
	}
	if !equalPrivateKeys(privateB, keys[keyTranslatorB].Private) {
		t.Errorf("Invalid private key for %s", testClientB)
	}

	// AcraServer's peer is AcraConnector. It expects AcraConnector's keys.

	publicA, err := keyStore.GetPeerPublicKey(testClientA)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientA, err)
	}
	if !equalPublicKeys(publicA, keys[keyConnectorA].Public) {
		t.Errorf("Invalid public key for %s", testClientA)
	}

	publicB, err := keyStore.GetPeerPublicKey(testClientB)
	if err != nil {
		t.Fatalf("Failed to get public key for %s: %v", testClientB, err)
	}
	if !equalPublicKeys(publicB, keys[keyConnectorB].Public) {
		t.Errorf("Invalid public key for %s", testClientB)
	}
}
