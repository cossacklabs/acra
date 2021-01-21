package network

import (
	"context"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/peer"
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

func TestSecureSessionGRPCClientIDExtractorSuccess(t *testing.T){
	expectedClientID := []byte("client id")
	authInfo := SecureSessionInfo{clientID: expectedClientID}
	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: authInfo})
	secureSessionExtractor, err := NewSecureSessionGRPCClientIDExtractor()
	if err != nil {
		t.Fatal(err)
	}
	resultClientID, err := secureSessionExtractor.ExtractClientID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, resultClientID, expectedClientID)
}

func TestSecureSessionClientIDExtractorInvalidContext(t *testing.T){
	extractor, err := NewSecureSessionGRPCClientIDExtractor()
	if err != nil {
		t.Fatal(err)
	}
	testRPCClientIDExtractorInvalidContext(extractor, t)
}

func TestSecureSessionClientIDExtractorIncorrectAuthInfo(t *testing.T){
	ctx := context.Background()
	ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: SecureSessionInfo{}})
	extractor, err := NewSecureSessionGRPCClientIDExtractor()
	if err != nil {
		t.Fatal(err)
	}
	testTLSGRPCClientIDExtractorIncorrectAuthInfo(extractor, t)
}