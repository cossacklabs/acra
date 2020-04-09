/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package base_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	acrawriter "github.com/cossacklabs/acra/acra-writer"
	// use another package name and explicit import to avoid cyclic import
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestDecryptAcrastruct(t *testing.T) {
	testData := make([]byte, 1000)
	_, err := rand.Read(testData)
	if err != nil {
		t.Fatal(err)
	}
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}

	acrastruct, err := acrawriter.CreateAcrastruct(testData, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}

	// test error on short acrastruct
	_, err = base.DecryptAcrastruct([]byte("short data"), keypair.Private, nil)
	if err != base.ErrIncorrectAcraStructLength {
		t.Fatal("incorrect error")
	}

	// test acrastruct with incorrect data length

	// replace data length value by zeroes
	incorrectAcraStruct := append([]byte{}, acrastruct[:base.GetMinAcraStructLength()-base.DataLengthSize]...)
	incorrectAcraStruct = append(incorrectAcraStruct, bytes.Repeat([]byte{0}, base.DataLengthSize)...)
	incorrectAcraStruct = append(incorrectAcraStruct, acrastruct[base.GetMinAcraStructLength():]...)
	_, err = base.DecryptAcrastruct(incorrectAcraStruct, keypair.Private, nil)
	if err != base.ErrIncorrectAcraStructDataLength {
		t.Fatal("incorrect error")
	}

	decrypted, err := base.DecryptAcrastruct(acrastruct, keypair.Private, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("decrypted != test_data")
	}

	t.Log("Test with zone")
	zone_id := zone.GenerateZoneID()
	acrastruct, err = acrawriter.CreateAcrastruct(testData, keypair.Public, zone_id)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = base.DecryptAcrastruct(acrastruct, keypair.Private, zone_id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("decrypted != test_data")
	}
}

func TestValidateAcraStructLength(t *testing.T) {
	testData := make([]byte, 1000)
	_, err := rand.Read(testData)
	if err != nil {
		t.Fatal(err)
	}
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}

	acrastruct, err := acrawriter.CreateAcrastruct(testData, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	// incorrect TagBegin
	if err := base.ValidateAcraStructLength(acrastruct[1:]); err != base.ErrIncorrectAcraStructTagBegin {
		t.Fatal("Incorrect validation of TagBegin")
	}
	// test short AcraStruct
	if err := base.ValidateAcraStructLength(acrastruct[:base.GetMinAcraStructLength()-1]); err != base.ErrIncorrectAcraStructLength {
		t.Fatal("Incorrect validation of minimal AcraStruct length")
	}
	// test long AcraStruct
	if err := base.ValidateAcraStructLength(append(acrastruct, 1)); err != base.ErrIncorrectAcraStructDataLength {
		t.Fatal("Incorrect validation of AcraStruct length")
	}
	// test with incorrect data length value
	// change value of data length by incrementing any of bytes
	testData[base.GetMinAcraStructLength()-base.DataLengthSize]++
	// test long AcraStruct
	if err := base.ValidateAcraStructLength(append(acrastruct, 1)); err != base.ErrIncorrectAcraStructDataLength {
		t.Fatal("Incorrect validation of AcraStruct data length")
	}
}
