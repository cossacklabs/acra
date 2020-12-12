package network

import (
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
)

type SimpleKeyStore struct {
	PrivateKey *keys.PrivateKey
	PublicKey  *keys.PublicKey
}

func (keystore *SimpleKeyStore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	return keystore.PrivateKey, nil
}
func (keystore *SimpleKeyStore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	return keystore.PublicKey, nil
}

func TestSessionWrapper(t *testing.T) {
	clientPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	var testClientID = []byte("client")
	var testServerID = []byte("server")
	clientWrapper, err := NewSecureSessionConnectionWrapperWithServerID(testClientID, testServerID, &SimpleKeyStore{PrivateKey: clientPair.Private, PublicKey: serverPair.Public})
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewSecureSessionConnectionWrapper(testServerID, &SimpleKeyStore{PrivateKey: serverPair.Private, PublicKey: clientPair.Public})
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, testClientID, wrapperCommunicationIterations, t)
}

func BenchmarkSessionWrapper(t *testing.B) {
	clientPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	var testClientID = []byte("client")
	var testServerID = []byte("server")
	clientWrapper, err := NewSecureSessionConnectionWrapperWithServerID(testClientID, testServerID, &SimpleKeyStore{PrivateKey: clientPair.Private, PublicKey: serverPair.Public})
	if err != nil {
		t.Fatal(err)
	}
	serverWrapper, err := NewSecureSessionConnectionWrapper(testServerID, &SimpleKeyStore{PrivateKey: serverPair.Private, PublicKey: clientPair.Public})
	if err != nil {
		t.Fatal(err)
	}
	testWrapper(clientWrapper, serverWrapper, testClientID, t.N, t)
}
