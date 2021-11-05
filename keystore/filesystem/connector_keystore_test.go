package filesystem

import (
	"io/ioutil"
	"os"
	"testing"

	connector_mode "github.com/cossacklabs/acra/cmd/acra-connector/connector-mode"
)

// TestConnectorFileSystemKeyStoreBuilder_Build test raw Build() call, validation and expected errors, check setup
// default values
func TestConnectorFileSystemKeyStoreBuilder_Build(t *testing.T) {
	dirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dirName)
	store := NewCustomConnectorFileSystemKeyStore()

	_, err = store.Build()
	if err != nil && err.Error() != "private key directory not specified" {
		t.Fatal(err)
	}
	store.KeyDirectory(dirName)

	_, err = store.Build()
	if err != nil && err.Error() != "client ID not specified" {
		t.Fatal(err)
	}
	store.ClientID([]byte("client id"))

	_, err = store.Build()
	if err != nil && err.Error() != "encryptor not specified" {
		t.Fatal(err)
	}
	store.Encryptor(dummyEncryptor{})

	_, err = store.Build()
	if err != nil && err.Error() != "connector mode not specified" {
		t.Fatal(err)
	}
	store.ConnectorMode(connector_mode.AcraServerMode)
	_, err = store.Build()
	if err != nil && err.Error() != "connector mode not specified" {
		t.Fatal(err)
	}

	_, err = store.Build()
	if err != nil {
		t.Fatal(err)
	}
}
