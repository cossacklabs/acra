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

package filesystem

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cossacklabs/acra/keystore/v2/keystore/api"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	backend "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	backendAPI "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
)

var (
	testMasterKey    = []byte("test master key")
	testSignatureKey = []byte("test signature key")
)

func testKeyStoreSuite(t *testing.T) *crypto.KeyStoreSuite {
	encryptor, err := crypto.NewSCellSuite(testMasterKey, testSignatureKey)
	if err != nil {
		t.Fatalf("cannot create encryptor: %v", err)
	}
	return encryptor
}

func newInMemoryKeyStore(t *testing.T) api.MutableKeyStore {
	store, err := NewInMemory(testKeyStoreSuite(t))
	if err != nil {
		t.Fatalf("cannot create in-memory keystore: %v", err)
	}
	return store
}

func testFilesystemKeyStore(t *testing.T) (func(t *testing.T) api.MutableKeyStore, func()) {
	rootTestDir, err := ioutil.TempDir(os.TempDir(), "keystore-test")
	if err != nil {
		t.Fatalf("cannot create root test directory: %v", err)
	}
	cleanup := func() { os.RemoveAll(rootTestDir) }
	spawn := func(t *testing.T) api.MutableKeyStore {
		testDir, err := ioutil.TempDir(rootTestDir, "keystore-test")
		if err != nil {
			t.Fatalf("cannot create test directory: %v", err)
		}
		store, err := OpenDirectoryRW(testDir, testKeyStoreSuite(t))
		if err != nil {
			t.Fatalf("failed to create key store: %v", err)
		}
		return store
	}
	return spawn, cleanup
}

func TestKeyStoreOpeningDir(t *testing.T) {
	testDir, err := ioutil.TempDir(os.TempDir(), "keystore-test")
	if err != nil {
		t.Fatalf("cannot create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	rootPath := filepath.Join(testDir, "root")

	if IsKeyDirectory(rootPath) {
		t.Errorf("missing directory cannot be IsKeyDirectory()")
	}

	_, err = OpenDirectory(rootPath, testKeyStoreSuite(t))
	if err != backendAPI.ErrNotExist {
		t.Errorf("opened non-existant key store: %v", err)
	}

	if IsKeyDirectory(rootPath) {
		t.Errorf("OpenDirectory() should not create key directory")
	}

	_, err = OpenDirectoryRW(rootPath, testKeyStoreSuite(t))
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}

	fi, err := os.Stat(rootPath)
	if err != nil {
		t.Fatalf("failed to stat root directory: %v", err)
	}
	if !fi.IsDir() {
		t.Errorf("root key directory is not directory")
	}

	if !IsKeyDirectory(rootPath) {
		t.Errorf("OpenDirectoryRW() must create key directory")
	}

	_, err = OpenDirectory(rootPath, testKeyStoreSuite(t))
	if err != nil {
		t.Errorf("failed to open created key directory: %v", err)
	}

	err = os.Chmod(rootPath, os.FileMode(0777))
	if err != nil {
		t.Fatalf("failed to chmod root directory: %v", err)
	}

	_, err = OpenDirectory(rootPath, testKeyStoreSuite(t))
	if err != backend.ErrInvalidPermissions {
		t.Errorf("opened a directory with incorrect permissions: %v", err)
	}

	_, err = OpenDirectoryRW(rootPath, testKeyStoreSuite(t))
	if err != backend.ErrInvalidPermissions {
		t.Errorf("opened a directory with incorrect permissions (RW): %v", err)
	}

	err = os.RemoveAll(rootPath)
	if err != nil {
		t.Fatalf("failed to remove root directory: %v", err)
	}
	f, err := os.Create(rootPath)
	if err != nil {
		t.Fatalf("failed to create file instead of root directory: %v", err)
	}
	f.Close()

	_, err = OpenDirectory(rootPath, testKeyStoreSuite(t))
	if err != backend.ErrNotDirectory {
		t.Errorf("opened a file instead of directory: %v", err)
	}
}

func TestKeyStoreOpeningRings(t *testing.T) {
	s, err := NewInMemory(testKeyStoreSuite(t))
	if err != nil {
		t.Fatalf("cannot create in-memory keystore: %v", err)
	}

	_, err = s.OpenKeyRing("some/keyring")
	if err != backendAPI.ErrNotExist {
		t.Errorf("opened non-existant key ring: %v", err)
	}

	_, err = s.OpenKeyRingRW("some/keyring")
	if err != nil {
		t.Errorf("failed to create key ring: %v", err)
	}

	_, err = s.OpenKeyRing("some/keyring")
	if err != nil {
		t.Errorf("failed to open created key ring: %v", err)
	}
}

func TestKeyStorePersistence(t *testing.T) {
	testDir, err := ioutil.TempDir(os.TempDir(), "keystore-test")
	if err != nil {
		t.Fatalf("cannot create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	s1, err := OpenDirectoryRW(testDir, testKeyStoreSuite(t))
	if err != nil {
		t.Fatalf("failed to open key store: %v", err)
	}
	s1.OpenKeyRingRW("my-keyring")
	if err != nil {
		t.Errorf("failed to create key ring: %v", err)
	}

	s2, err := OpenDirectory(testDir, testKeyStoreSuite(t))
	if err != nil {
		t.Fatalf("failed to open key store (read-only): %v", err)
	}
	s2.OpenKeyRing("my-keyring")
	if err != nil {
		t.Errorf("failed to open key ring: %v", err)
	}
}
