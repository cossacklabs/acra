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
