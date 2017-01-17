// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package keystore_test

import (
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSystemKeyKeyStore(t *testing.T) {
	key_directory := fmt.Sprintf(".%s%s", string(filepath.Separator), "keys")
	os.MkdirAll(key_directory, 0700)
	defer func() {
		os.RemoveAll(key_directory)
	}()
	store, err := keystore.NewFilesystemKeyStore(key_directory)
	if err != nil {
		t.Fatal("error")
	}
	if store.HasZonePrivateKey([]byte("non-existent key")) {
		t.Fatal("Expected false on non-existent key")
	}
	key, err := store.GetZonePrivateKey([]byte("non-existent key"))
	if err == nil {
		t.Fatal("Expected any error")
	}
	if key != nil {
		t.Fatal("Non-expected key")
	}
	id, _, err := store.GenerateZoneKey()
	if err != nil {
		t.Fatal(err)
	}
	if !store.HasZonePrivateKey(id) {
		t.Fatal("Expected true on existed id")
	}
	key, err = store.GetZonePrivateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("Expected private key")
	}
}

func test_reset(store *FilesystemKeyStore, t *testing.T) {
	test_id := []byte("some test id")
	if err := store.GenerateServerKeys(test_id); err != nil{
		t.Fatal(err)
	}
	if _, err :=store.GetServerPrivateKey(test_id); err != nil{
		t.Fatal(err)
	}
	store.Reset()
	if err := os.Remove(store.get_file_path(store.get_server_key_filename(test_id))); err != nil{
		t.Fatal(err)
	}
	if err := os.Remove(fmt.Sprintf("%s.pub", store.get_file_path(store.get_server_key_filename(test_id)))); err != nil{
		t.Fatal(err)
	}

	if _, err :=store.GetServerPrivateKey(test_id); err == nil{
		t.Fatal("Expected error on fetching cleared key")
	}
}

	test_reset(store, t)