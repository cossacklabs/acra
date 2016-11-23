package keystore_test

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/themis/gothemis/keys"
	"os"
	"path/filepath"
	"testing"
)

func TestOneKeyKeyStore(t *testing.T) {
	key_pair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	store := keystore.NewOneKeyStore(key_pair.Private)
	// on any id it return true
	if !store.HasKey([]byte("random id 1")) {
		t.Fatal("Store hasn't key but should have")
	}
	if !store.HasKey([]byte("random id 2")) {
		t.Fatal("Store hasn't key but should have")
	}
	key1, err := store.GetKey([]byte("random 1"))
	if err != nil {
		t.Fatal(err)
	}
	key2, err := store.GetKey([]byte("random 2"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(key1.Value, key2.Value) != 0 {
		t.Fatal("All keys should be equal")
	}
	id1, public_key1, err := store.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id2, public_key2, err := store.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(id1, id2) == 0 {
		t.Fatal("Id's is equals but should be random")
	}
	if bytes.Compare(public_key1, public_key2) != 0 {
		t.Fatal("Public keys should be equals but they are different")
	}
}
func TestFileSystemKeyKeyStore(t *testing.T) {
	key_directory := fmt.Sprintf(".%s%s", string(filepath.Separator), "keys")
	os.MkdirAll(key_directory, 0700)
	defer func() {
		os.RemoveAll(key_directory)
	}()
	store := keystore.NewFilesystemKeyStore(key_directory)
	if store.HasKey([]byte("non-existent key")) {
		t.Fatal("Expected false on non-existent key")
	}
	key, err := store.GetKey([]byte("non-existent key"))
	if err == nil {
		t.Fatal("Expected any error")
	}
	if key != nil {
		t.Fatal("Non-expected key")
	}
	id, _, err := store.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !store.HasKey(id) {
		t.Fatal("Expected true on existed id")
	}
	key, err = store.GetKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("Expected private key")
	}
}
