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
	"crypto/subtle"
	"errors"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/asn1"
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
	t.Run("TestKeyStoreCleanImport", func(t *testing.T) {
		testKeyStoreCleanImport(t, newKeyStore)
	})
	t.Run("TestKeyStoreDuplicateImport", func(t *testing.T) {
		testKeyStoreDuplicateImport(t, newKeyStore)
	})
	t.Run("TestKeyStoreDuplicateImportSkip", func(t *testing.T) {
		testKeyStoreDuplicateImportSkip(t, newKeyStore)
	})
	t.Run("TestKeyStoreDuplicateImportOverwrite", func(t *testing.T) {
		testKeyStoreDuplicateImportOverwrite(t, newKeyStore)
	})
	t.Run("TestKeyStoreListing", func(t *testing.T) {
		testKeyStoreListing(t, newKeyStore)
	})
	t.Run("TestKeyStoreExportPublicOnly", func(t *testing.T) {
		testKeyStoreExportPublicOnly(t, newKeyStore)
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

var (
	demoPublicKeyData    = []byte("public key")
	demoPrivateKeyData   = []byte("private key")
	demoSymmetricKeyData = []byte("symmetric key")
)

func setupDemoKeyStore(s api.MutableKeyStore, t *testing.T) {
	ringKeyPair, err := s.OpenKeyRingRW(exportRingKeyPair)
	if err != nil {
		t.Errorf("failed to create key ring: %v", err)
	}
	_, err = ringKeyPair.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			{
				Format:     api.ThemisKeyPairFormat,
				PublicKey:  demoPublicKeyData,
				PrivateKey: demoPrivateKeyData,
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
			{
				Format:    api.ThemisKeyPairFormat,
				PublicKey: demoPublicKeyData,
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
			{
				Format:       api.ThemisSymmetricKeyFormat,
				SymmetricKey: demoSymmetricKeyData,
			},
		},
	})
	if err != nil {
		t.Errorf("failed to add public key: %v", err)
	}
}

func checkDemoKeyRingKeyPair(t *testing.T, ring api.KeyRing) {
	checkDemoKeyRingKeyPairData(t, ring, true)
}

func checkDemoKeyRingKeyPairOnlyPublic(t *testing.T, ring api.KeyRing) {
	checkDemoKeyRingKeyPairData(t, ring, false)
}

func checkDemoKeyRingKeyPairData(t *testing.T, ring api.KeyRing, expectPrivateKey bool) {
	seqnums, err := ring.AllKeys()
	if err != nil {
		t.Errorf("cannot get seqnums: %v", err)
		return
	}
	if len(seqnums) != 1 {
		t.Errorf("invalid seqnum count: %d", len(seqnums))
		return
	}
	publicKey, err := ring.PublicKey(seqnums[0], api.ThemisKeyPairFormat)
	if err != nil {
		t.Errorf("cannot get public key data: %v", err)
	}
	if subtle.ConstantTimeCompare(publicKey, demoPublicKeyData) != 1 {
		t.Errorf("incorrect public key data")
	}
	privateKey, err := ring.PrivateKey(seqnums[0], api.ThemisKeyPairFormat)
	if expectPrivateKey {
		if err != nil {
			t.Errorf("cannot get private key data: %v", err)
		}
		if subtle.ConstantTimeCompare(privateKey, demoPrivateKeyData) != 1 {
			t.Errorf("incorrect private key data")
		}
	} else {
		if err != api.ErrNoKeyData {
			t.Errorf("unexpected private key present: %v", err)
		}
	}
}

func checkDemoKeyRingPublic(t *testing.T, ring api.KeyRing) {
	seqnums, err := ring.AllKeys()
	if err != nil {
		t.Errorf("cannot get seqnums: %v", err)
		return
	}
	if len(seqnums) != 1 {
		t.Errorf("invalid seqnum count: %d", len(seqnums))
		return
	}
	publicKey, err := ring.PublicKey(seqnums[0], api.ThemisKeyPairFormat)
	if err != nil {
		t.Errorf("cannot get public key data: %v", err)
	}
	_, err = ring.PrivateKey(seqnums[0], api.ThemisKeyPairFormat)
	if err != api.ErrNoKeyData {
		t.Errorf("unexpected error for private key data: %v", err)
	}
	if subtle.ConstantTimeCompare(publicKey, demoPublicKeyData) != 1 {
		t.Errorf("incorrect public key data")
	}
}

func checkDemoKeyRingSymmetric(t *testing.T, ring api.KeyRing) {
	seqnums, err := ring.AllKeys()
	if err != nil {
		t.Errorf("cannot get seqnums of public key ring: %v", err)
		return
	}
	if len(seqnums) != 1 {
		t.Errorf("invalid seqnum count: %d", len(seqnums))
		return
	}
	symmetricKey, err := ring.SymmetricKey(seqnums[0], api.ThemisSymmetricKeyFormat)
	if err != nil {
		t.Errorf("cannot get symmetric key data: %v", err)
	}
	if subtle.ConstantTimeCompare(symmetricKey, demoSymmetricKeyData) != 1 {
		t.Errorf("incorrect symmetric key data")
	}
}

func equalStringList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type stubImportDelegate struct {
	decision api.ImportDecision
	err      error
}

func (s *stubImportDelegate) DecideKeyRingOverwrite(currentData, newData *asn1.KeyRing) (api.ImportDecision, error) {
	return s.decision, s.err
}

func testKeyStoreCleanImport(t *testing.T, newKeyStore NewKeyStore) {
	s := newKeyStore(t)
	setupDemoKeyStore(s, t)
	cryptosuite := newExportStoreSuite(t)

	exported, err := s.ExportKeyRings(exportRingAll, cryptosuite, api.ExportPrivateKeys)
	if err != nil {
		t.Fatalf("failed to export key rings: %v", err)
	}

	s2 := newKeyStore(t)

	imported, err := s2.ImportKeyRings(exported, cryptosuite, nil)
	if err != nil {
		t.Fatalf("failed to import key rings: %v", err)
	}
	if !equalStringList(imported, exportRingAll) {
		t.Errorf("incorrect imported list: %v", imported)
	}

	ringKeyPair, err := s2.OpenKeyRing(exportRingKeyPair)
	if err != nil {
		t.Errorf("cannot open key ring with key pair: %v", err)
	} else {
		checkDemoKeyRingKeyPair(t, ringKeyPair)
	}

	ringPublic, err := s2.OpenKeyRing(exportRingPublic)
	if err != nil {
		t.Errorf("cannot open key ring with public key: %v", err)
	} else {
		checkDemoKeyRingPublic(t, ringPublic)
	}

	ringSymmetric, err := s2.OpenKeyRing(exportRingSymmetric)
	if err != nil {
		t.Errorf("cannot open key ring with symmetric key: %v", err)
	} else {
		checkDemoKeyRingSymmetric(t, ringSymmetric)
	}
}

func testKeyStoreDuplicateImport(t *testing.T, newKeyStore NewKeyStore) {
	s := newKeyStore(t)
	s2 := newKeyStore(t)
	setupDemoKeyStore(s, t)
	cryptosuite := newExportStoreSuite(t)

	keyRingList := []string{exportRingPublic}
	exported1, err := s.ExportKeyRings(keyRingList, cryptosuite, api.ExportPrivateKeys)
	if err != nil {
		t.Fatalf("failed to export public key ring: %v", err)
	}

	imported1, err := s2.ImportKeyRings(exported1, cryptosuite, nil)
	if err != nil {
		t.Fatalf("failed to import public key ring: %v", err)
	}
	if !equalStringList(imported1, keyRingList) {
		t.Errorf("incorrect imported list: %v", imported1)
	}

	exported2, err := s.ExportKeyRings([]string{exportRingKeyPair, exportRingPublic, exportRingSymmetric}, cryptosuite, api.ExportPrivateKeys)
	if err != nil {
		t.Fatalf("failed to export key rings: %v", err)
	}

	duplicateError := errors.New("duplicate detected")
	delegate := &stubImportDelegate{
		decision: api.ImportAbort,
		err:      duplicateError,
	}
	imported2, err := s2.ImportKeyRings(exported2, cryptosuite, delegate)
	if err != duplicateError {
		t.Fatalf("duplicate import should be aborted: %v", err)
	}
	if !equalStringList(imported2, nil) {
		t.Errorf("incorrect imported list: %v", imported2)
	}

	// Note that key exported key pair has been imported successfully, the process aborted at public key
	ringKeyPair, err := s2.OpenKeyRing(exportRingKeyPair)
	if err != nil {
		t.Errorf("cannot open key ring with key pair: %v", err)
	} else {
		checkDemoKeyRingKeyPair(t, ringKeyPair)
	}

	ringPublic, err := s2.OpenKeyRing(exportRingPublic)
	if err != nil {
		t.Errorf("cannot open key ring with public key: %v", err)
	} else {
		checkDemoKeyRingPublic(t, ringPublic)
	}

	_, err = s2.OpenKeyRing(exportRingSymmetric)
	if err == nil {
		t.Errorf("symmetric key should not be imported: %v", err)
	}
}

func testKeyStoreDuplicateImportSkip(t *testing.T, newKeyStore NewKeyStore) {
	s := newKeyStore(t)
	s2 := newKeyStore(t)
	setupDemoKeyStore(s, t)
	cryptosuite := newExportStoreSuite(t)

	keyRingList1 := []string{exportRingPublic}
	exported1, err := s.ExportKeyRings(keyRingList1, cryptosuite, api.ExportPrivateKeys)
	if err != nil {
		t.Fatalf("failed to export public key ring: %v", err)
	}

	imported1, err := s2.ImportKeyRings(exported1, cryptosuite, nil)
	if err != nil {
		t.Fatalf("failed to import public key ring: %v", err)
	}
	if !equalStringList(imported1, keyRingList1) {
		t.Errorf("incorrect imported list: %v", imported1)
	}

	keyRingList2 := []string{exportRingKeyPair, exportRingPublic, exportRingSymmetric}
	exported2, err := s.ExportKeyRings(keyRingList2, cryptosuite, api.ExportPrivateKeys)
	if err != nil {
		t.Fatalf("failed to export key rings: %v", err)
	}

	delegate := &stubImportDelegate{
		decision: api.ImportSkip,
	}
	imported2, err := s2.ImportKeyRings(exported2, cryptosuite, delegate)
	if err != nil {
		t.Fatalf("duplicate import should be skipped: %v", err)
	}
	if !equalStringList(imported2, keyRingList2) {
		t.Errorf("incorrect imported list: %v", imported2)
	}

	// Now all three key rings are imported without issue. Already present public key
	// is simply skipped.
	ringKeyPair, err := s2.OpenKeyRing(exportRingKeyPair)
	if err != nil {
		t.Errorf("cannot open key ring with key pair: %v", err)
	} else {
		checkDemoKeyRingKeyPair(t, ringKeyPair)
	}

	ringPublic, err := s2.OpenKeyRing(exportRingPublic)
	if err != nil {
		t.Errorf("cannot open key ring with public key: %v", err)
	} else {
		checkDemoKeyRingPublic(t, ringPublic)
	}

	ringSymmetric, err := s2.OpenKeyRing(exportRingSymmetric)
	if err != nil {
		t.Errorf("cannot open key ring with symmetric key: %v", err)
	} else {
		checkDemoKeyRingSymmetric(t, ringSymmetric)
	}
}

func checkDemoKeyRingKeyPublicNew(t *testing.T, ring api.KeyRing, newSeqnum int) {
	seqnums, err := ring.AllKeys()
	if err != nil {
		t.Errorf("cannot get seqnums: %v", err)
		return
	}
	if len(seqnums) != 2 {
		t.Errorf("invalid seqnum count: %d", len(seqnums))
		return
	}
	if seqnums[0] != newSeqnum {
		t.Errorf("invalid seqnum[0]: %d", seqnums[1])
		return
	}

	current, err := ring.CurrentKey()
	if err != nil {
		t.Errorf("falied to get current: %v", err)
		return
	}
	if current != seqnums[0] {
		t.Errorf("invalid current: %d", current)
		return
	}

	publicKey, err := ring.PublicKey(seqnums[1], api.ThemisKeyPairFormat)
	if err != nil {
		t.Errorf("cannot get public key data: %v", err)
	}
	_, err = ring.PrivateKey(seqnums[1], api.ThemisKeyPairFormat)
	if err != api.ErrNoKeyData {
		t.Errorf("unexpected error for private key data: %v", err)
	}
	if subtle.ConstantTimeCompare(publicKey, demoPublicKeyData) != 1 {
		t.Errorf("incorrect public key data")
	}

	publicKey2, err := ring.PublicKey(seqnums[0], api.ThemisKeyPairFormat)
	if err != nil {
		t.Errorf("cannot get public key data: %v", err)
	}
	_, err = ring.PrivateKey(seqnums[0], api.ThemisKeyPairFormat)
	if err != api.ErrNoKeyData {
		t.Errorf("unexpected error for private key data: %v", err)
	}
	if subtle.ConstantTimeCompare(publicKey2, []byte("another public key")) != 1 {
		t.Errorf("incorrect public key data")
	}

}

func testKeyStoreDuplicateImportOverwrite(t *testing.T, newKeyStore NewKeyStore) {
	s := newKeyStore(t)
	s2 := newKeyStore(t)
	setupDemoKeyStore(s, t)
	cryptosuite := newExportStoreSuite(t)

	keyRingList1 := []string{exportRingPublic}
	exported1, err := s.ExportKeyRings(keyRingList1, cryptosuite, api.ExportPrivateKeys)
	if err != nil {
		t.Fatalf("failed to export public key ring: %v", err)
	}

	imported1, err := s2.ImportKeyRings(exported1, cryptosuite, nil)
	if err != nil {
		t.Fatalf("failed to import public key ring: %v", err)
	}
	if !equalStringList(imported1, keyRingList1) {
		t.Errorf("incorrect imported list: %v", imported1)
	}

	ringPublic1, err := s.OpenKeyRingRW(exportRingPublic)
	if err != nil {
		t.Fatalf("failed to open public key ring: %v", err)
	}

	newSeqnum, err := ringPublic1.AddKey(api.KeyDescription{
		ValidSince: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
		Data: []api.KeyData{
			{
				Format:    api.ThemisKeyPairFormat,
				PublicKey: []byte("another public key"),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to add new public key: %v", err)
	}
	err = ringPublic1.SetCurrent(newSeqnum)
	if err != nil {
		t.Fatalf("failed to set new public key current: %v", err)
	}

	keyRingList2 := []string{exportRingKeyPair, exportRingPublic, exportRingSymmetric}
	exported2, err := s.ExportKeyRings(keyRingList2, cryptosuite, api.ExportPrivateKeys)
	if err != nil {
		t.Fatalf("failed to export key rings: %v", err)
	}

	delegate := &stubImportDelegate{
		decision: api.ImportOverwrite,
	}
	imported2, err := s2.ImportKeyRings(exported2, cryptosuite, delegate)
	if err != nil {
		t.Fatalf("duplicate import should be overwritten: %v", err)
	}
	if !equalStringList(imported2, keyRingList2) {
		t.Errorf("incorrect imported list: %v", imported2)
	}

	// Now all three key rings are imported without issue. Already present public key
	// is overwritten with new data.
	ringKeyPair, err := s2.OpenKeyRing(exportRingKeyPair)
	if err != nil {
		t.Errorf("cannot open key ring with key pair: %v", err)
	} else {
		checkDemoKeyRingKeyPair(t, ringKeyPair)
	}

	ringPublic, err := s2.OpenKeyRing(exportRingPublic)
	if err != nil {
		t.Errorf("cannot open key ring with public key: %v", err)
	} else {
		checkDemoKeyRingKeyPublicNew(t, ringPublic, newSeqnum)
	}

	ringSymmetric, err := s2.OpenKeyRing(exportRingSymmetric)
	if err != nil {
		t.Errorf("cannot open key ring with symmetric key: %v", err)
	} else {
		checkDemoKeyRingSymmetric(t, ringSymmetric)
	}
}

func testKeyStoreListing(t *testing.T, newKeyStore NewKeyStore) {
	s := newKeyStore(t)

	keyRingsBefore, err := s.ListKeyRings()
	if err != nil {
		t.Fatalf("cannot list key rings: %v", err)
	}

	setupDemoKeyStore(s, t)

	keyRingsAfter, err := s.ListKeyRings()
	if err != nil {
		t.Fatalf("cannot list key rings: %v", err)
	}

	if len(keyRingsBefore) != 0 {
		t.Errorf("keystore is not empty initially")
	}

	if len(keyRingsAfter) != 3 {
		t.Fatalf("incorrect key ring count after setup")
	}
	if (keyRingsAfter[0] != exportRingKeyPair) || (keyRingsAfter[1] != exportRingPublic) || (keyRingsAfter[2] != exportRingSymmetric) {
		t.Errorf("incorrect listing content: %v", keyRingsAfter)
	}
}

func testKeyStoreExportPublicOnly(t *testing.T, newKeyStore NewKeyStore) {
	s := newKeyStore(t)
	setupDemoKeyStore(s, t)
	cryptosuite := newExportStoreSuite(t)

	exported, err := s.ExportKeyRings(exportRingAll, cryptosuite, api.ExportPublicOnly)
	if err != nil {
		t.Fatalf("failed to export key rings: %v", err)
	}

	s2 := newKeyStore(t)

	imported, err := s2.ImportKeyRings(exported, cryptosuite, nil)
	if err != nil {
		t.Fatalf("failed to import key rings: %v", err)
	}
	if !equalStringList(imported, []string{exportRingKeyPair, exportRingPublic}) {
		t.Errorf("incorrect imported list: %v", imported)
	}

	ringKeyPair, err := s2.OpenKeyRing(exportRingKeyPair)
	if err != nil {
		t.Errorf("cannot open key ring with key pair: %v", err)
	} else {
		checkDemoKeyRingKeyPairOnlyPublic(t, ringKeyPair)
	}

	ringPublic, err := s2.OpenKeyRing(exportRingPublic)
	if err != nil {
		t.Errorf("cannot open key ring with public key: %v", err)
	} else {
		checkDemoKeyRingPublic(t, ringPublic)
	}

	// We can't be specific with error here since it depends on the backend :(
	// It's typically "ErrNotExist" for filesystem backends.
	ringSymmetric, err := s2.OpenKeyRing(exportRingSymmetric)
	if err == nil || ringSymmetric != nil {
		t.Errorf("symmetric key not skipped")
	}
}
