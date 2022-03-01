package crypto

import (
	"context"
	"crypto/rand"
	acrablock2 "github.com/cossacklabs/acra/acrablock"
	acrastruct2 "github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
)

func TestEnvelopeMatcher(t *testing.T) {
	matcher := NewEnvelopeMatcher()
	testData := []byte(`some data`)
	symKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	acrastruct, err := acrastruct2.CreateAcrastruct(testData, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	acrablock, err := acrablock2.CreateAcraBlock(testData, symKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	type testcase struct {
		data  []byte
		match bool
	}
	keyStore := mocks.ServerKeyStore{}
	InitRegistry(&keyStore)
	clientID := []byte(`client id`)
	keyStore.On("GetClientIDSymmetricKeys", clientID).Return(func([]byte) [][]byte {
		return [][]byte{append([]byte{}, symKey...)}
	}, nil)
	keyStore.On("GetClientIDSymmetricKey", clientID).Return(func([]byte) []byte {
		return append([]byte{}, symKey...)
	}, nil)
	keyStore.On("GetClientIDEncryptionPublicKey", clientID).Return(func([]byte) *keys.PublicKey {
		return &keys.PublicKey{Value: keypair.Public.Value}
	}, nil)

	testcases := make([]testcase, 4)
	// test pure acrastruct and acrablock
	testcases = append(testcases, testcase{acrastruct, true})
	testcases = append(testcases, testcase{acrablock, true})
	// test invalid data. it should be long enough to looks like longest crypto envelope: CryptoEnveloped AcraStruct
	fakeData := make([]byte, 300)
	if n, err := rand.Read(fakeData); err != nil {
		t.Fatal(err)
	} else if n != 300 {
		t.Fatal("Can't generate enough random data")
	}
	testcases = append(testcases, testcase{fakeData, false})

	dataContext := encryptor.DataEncryptorContext{Context: context.TODO(), Keystore: &keyStore}
	// add testcases for every known CryptoEnvelope in our registry
	for _, handler := range registry.envelopes {
		data, err := handler.EncryptWithClientID(clientID, testData, &dataContext)
		if err != nil {
			t.Fatal(err)
		}
		testcases = append(testcases, testcase{data, true})
	}

	for i, tcase := range testcases {
		matched := matcher.Match(tcase.data)
		if tcase.match != matched {
			t.Fatalf("TestCase %d not passed. %v != %v\n", i, tcase.match, matched)
		}
	}
}
