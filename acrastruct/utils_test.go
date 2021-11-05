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
package acrastruct

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/message"
	"testing"

	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestCreateAcrastruct(t *testing.T) {
	acraKp, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	dataSize := 1024
	someData := make([]byte, dataSize)

	n, err := rand.Read(someData)
	if err != nil || n != dataSize {
		t.Fatal(err)
	}

	acraStruct, err := CreateAcrastruct(someData, acraKp.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(acraStruct[:len(TagBegin)], TagBegin) != 0 {
		t.Fatal("Acrastruct has incorrect tag begin")
	}
	publicKey := acraStruct[len(TagBegin) : len(TagBegin)+PublicKeyLength]
	smessage := message.New(acraKp.Private, &keys.PublicKey{Value: publicKey})
	wrappedKey := acraStruct[len(TagBegin)+PublicKeyLength : len(TagBegin)+KeyBlockLength]

	unwrappedKey, err := smessage.Unwrap(wrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	scell, err := cell.SealWithKey(&keys.SymmetricKey{Value: unwrappedKey})
	if err != nil {
		t.Fatal(err)
	}
	dateLengthBuf := acraStruct[len(TagBegin)+KeyBlockLength : len(TagBegin)+KeyBlockLength+DataLengthSize]
	dataLength := int(binary.LittleEndian.Uint64(dateLengthBuf))
	data := acraStruct[len(TagBegin)+KeyBlockLength+DataLengthSize:]
	if len(data) != dataLength {
		t.Fatal("Incorrect data length")
	}
	decryptedData, err := scell.Decrypt(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(decryptedData, someData) != 0 {
		t.Fatal("Decrypted data not equal to original data")
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

	acraStruct, err := CreateAcrastruct(testData, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	// incorrect TagBegin
	if err := ValidateAcraStructLength(acraStruct[1:]); err != ErrIncorrectAcraStructTagBegin {
		t.Fatal("Incorrect validation of TagBegin")
	}
	// test short AcraStruct
	if err := ValidateAcraStructLength(acraStruct[:GetMinAcraStructLength()-1]); err != ErrIncorrectAcraStructLength {
		t.Fatal("Incorrect validation of minimal AcraStruct length")
	}
	// test long AcraStruct
	if err := ValidateAcraStructLength(append(acraStruct, 1)); err != ErrIncorrectAcraStructDataLength {
		t.Fatal("Incorrect validation of AcraStruct length")
	}
	// test with incorrect data length value
	// change value of data length by incrementing any of bytes
	testData[GetMinAcraStructLength()-DataLengthSize]++
	// test long AcraStruct
	if err := ValidateAcraStructLength(append(acraStruct, 1)); err != ErrIncorrectAcraStructDataLength {
		t.Fatal("Incorrect validation of AcraStruct data length")
	}
}

type testAcraStructProcessor struct {
	matched int
	newData []byte
}

func (processor *testAcraStructProcessor) OnAcraStruct(_ context.Context, acraStruct []byte) ([]byte, error) {
	if err := ValidateAcraStructLength(acraStruct); err != nil {
		return acraStruct, err
	}
	processor.matched++
	return processor.newData, nil
}

func TestProcessAcraStructs(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	testData1 := make([]byte, 10)
	_, err = rand.Read(testData1)
	if err != nil {
		t.Fatal(err)
	}
	testData2 := make([]byte, 10)
	_, err = rand.Read(testData2)
	if err != nil {
		t.Fatal(err)
	}
	acrastruct1, err := CreateAcrastruct(testData1, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	acrastruct2, err := CreateAcrastruct(testData1, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	trash := make([]byte, 20)
	_, err = rand.Read(trash)
	if err != nil {
		t.Fatal(err)
	}
	// create test data with inlined acrastructs
	testData := make([]byte, 0, len(acrastruct1)+len(acrastruct2)+len(trash)*2)
	testData = append(testData, acrastruct1...)
	// add between acrastructs
	testData = append(testData, trash...)
	testData = append(testData, acrastruct2...)
	// add at the end to check correct writing tail of data
	testData = append(testData, trash...)
	// expect that all acrastructs will be replaced with trash value
	expectedData := make([]byte, 0, len(trash)*4)
	expectedData = append(expectedData, trash...)
	expectedData = append(expectedData, trash...)
	expectedData = append(expectedData, trash...)
	expectedData = append(expectedData, trash...)

	output := make([]byte, len(testData))

	// test saving to another buffer
	processor := testAcraStructProcessor{newData: trash}
	if output, err = ProcessAcraStructs(context.TODO(), testData, output[:0], &processor); err != nil {
		t.Fatal(err)
	}
	if processor.matched != 2 {
		t.Fatalf("Not matched all AcraStructs, 2 != %d\n", processor.matched)
	}
	if !bytes.Equal(expectedData, output) {
		t.Fatal("Invalid output")
	}

	// test saving to the same buffer
	processor.matched = 0
	if output, err = ProcessAcraStructs(context.TODO(), testData, testData, &processor); err != nil {
		t.Fatal(err)
	}
	if processor.matched != 2 {
		t.Fatalf("Not matched all AcraStructs, 2 != %d\n", processor.matched)
	}
	if !bytes.Equal(output, expectedData) {
		t.Fatal("Invalid output")
	}
	if !bytes.Equal(output, testData[:len(output)]) {
		t.Fatal("Incorrect replaced data in same buffer")
	}
}

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

	acraStruct, err := CreateAcrastruct(testData, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}

	// test error on short acrastruct
	_, err = DecryptAcrastruct([]byte("short data"), keypair.Private, nil)
	if err != ErrIncorrectAcraStructLength {
		t.Fatal("incorrect error")
	}

	// test acrastruct with incorrect data length

	// replace data length value by zeroes
	incorrectAcraStruct := append([]byte{}, acraStruct[:GetMinAcraStructLength()-DataLengthSize]...)
	incorrectAcraStruct = append(incorrectAcraStruct, bytes.Repeat([]byte{0}, DataLengthSize)...)
	incorrectAcraStruct = append(incorrectAcraStruct, acraStruct[GetMinAcraStructLength():]...)
	_, err = DecryptAcrastruct(incorrectAcraStruct, keypair.Private, nil)
	if err != ErrIncorrectAcraStructDataLength {
		t.Fatal("incorrect error")
	}

	decrypted, err := DecryptAcrastruct(acraStruct, keypair.Private, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("decrypted != test_data")
	}

	t.Log("Test with something like zone")
	// don't use zone.GenerateZoneID due to import cycle
	zoneID := make([]byte, 100)
	if _, err = rand.Read(zoneID); err != nil {
		t.Fatal(err)
	}
	acraStruct, err = CreateAcrastruct(testData, keypair.Public, zoneID)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err = DecryptAcrastruct(acraStruct, keypair.Private, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, testData) {
		t.Fatal("decrypted != test_data")
	}
}
