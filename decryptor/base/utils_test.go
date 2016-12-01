package base_test

import (
	"bytes"
	"crypto/rand"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
)

func TestDecryptAcrastruct(t *testing.T) {
	test_data := make([]byte, 1000)
	_, err := rand.Read(test_data)
	if err != nil {
		t.Fatal(err)
	}
	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}

	acrastruct, err := acrawriter.CreateAcrastruct(test_data, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := base.DecryptAcrastruct(acrastruct, keypair.Private, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, test_data) {
		t.Fatal("decrypted != test_data")
	}

	t.Log("Test with zone")
	zone_id := zone.GenerateZoneId()
	acrastruct, err = acrawriter.CreateAcrastruct(test_data, keypair.Public, zone_id)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = base.DecryptAcrastruct(acrastruct, keypair.Private, zone_id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, test_data) {
		t.Fatal("decrypted != test_data")
	}
}
