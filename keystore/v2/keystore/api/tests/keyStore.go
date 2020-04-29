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

// Package tests provides conformity test suite for KeyStore API.
package tests

import (
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
)

// NewKeyStore is a factory of KeyStore under testing.
type NewKeyStore func(t *testing.T) api.MutableKeyStore

const (
	exportRingKeyPair   = "keyring/keypair"
	exportRingPublic    = "keyring/public"
	exportRingSymmetric = "keyring/symmetric"
)

var exportRingAll = []string{
	exportRingKeyPair,
	exportRingPublic,
	exportRingSymmetric,
}

// TestKeyStore runs KeyStore test suite.
func TestKeyStore(t *testing.T, newKeyStore NewKeyStore) {
	t.Run("TestKeyStoreExport", func(t *testing.T) {
		testKeyStoreExport(t, newKeyStore)
	})
}

var (
	testExportMasterKey    = []byte("test export master key")
	testExportSignatureKey = []byte("test export signature key")
)

func newExportStoreSuite(t *testing.T) *crypto.KeyStoreSuite {
	encryptor, err := crypto.NewSCellSuite(testExportMasterKey, testExportSignatureKey)
	if err != nil {
		t.Fatalf("cannot create encryptor: %v", err)
	}
	return encryptor
}

func setupDemoKeyStore(s api.MutableKeyStore, t *testing.T) {
	ringKeyPair, err := s.OpenKeyRingRW(exportRingKeyPair)
	if err != nil {
		t.Errorf("failed to create key ring: %v", err)
	}
	_, err = ringKeyPair.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:     api.ThemisKeyPairFormat,
				PublicKey:  []byte("public key"),
				PrivateKey: []byte("private key"),
			},
		},
	})
	if err != nil {
		t.Errorf("failed to add key pair: %v", err)
	}

	ringPublic, err := s.OpenKeyRingRW(exportRingPublic)
	if err != nil {
		t.Errorf("failed to create key ring: %v", err)
	}
	_, err = ringPublic.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:    api.ThemisKeyPairFormat,
				PublicKey: []byte("only public key"),
			},
		},
	})
	if err != nil {
		t.Errorf("failed to add public key: %v", err)
	}

	ringSymmetric, err := s.OpenKeyRingRW(exportRingSymmetric)
	if err != nil {
		t.Errorf("failed to create key ring: %v", err)
	}
	_, err = ringSymmetric.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			api.KeyData{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: []byte("symmetric key"),
			},
		},
	})
	if err != nil {
		t.Errorf("failed to add public key: %v", err)
	}
}

func testKeyStoreExport(t *testing.T, newKeyStore NewKeyStore) {
	s := newKeyStore(t)
	setupDemoKeyStore(s, t)

	_, err := s.ExportKeyRings(exportRingAll, newExportStoreSuite(t))
	if err != nil {
		t.Errorf("failed to export key rings: %v", err)
	}
}
