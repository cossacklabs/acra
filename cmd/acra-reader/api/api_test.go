package api

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/themis/gothemis/keys"
	context "golang.org/x/net/context"
)

type testKeystore struct {
	PrivateKey *keys.PrivateKey
}

func (*testKeystore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	panic("implement me")
}

func (*testKeystore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	panic("implement me")
}

var ErrKeyNotFound = errors.New("some error")

func (keystore *testKeystore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	if keystore.PrivateKey != nil {
		return &keys.PrivateKey{Value: append([]byte{}, keystore.PrivateKey.Value...)}, nil
	}
	return nil, ErrKeyNotFound

}

func (*testKeystore) HasZonePrivateKey(id []byte) bool {
	panic("implement me")
}

func (keystore *testKeystore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	if keystore.PrivateKey != nil {
		return &keys.PrivateKey{Value: append([]byte{}, keystore.PrivateKey.Value...)}, nil
	}
	return nil, ErrKeyNotFound
}

func (*testKeystore) GenerateZoneKey() ([]byte, []byte, error) {
	panic("implement me")
}

func (*testKeystore) GenerateConnectorKeys(id []byte) error {
	panic("implement me")
}

func (*testKeystore) GenerateServerKeys(id []byte) error {
	panic("implement me")
}

func (*testKeystore) GenerateDataEncryptionKeys(id []byte) error {
	panic("implement me")
}

func (*testKeystore) GetPoisonKeyPair() (*keys.Keypair, error) {
	panic("implement me")
}

func (*testKeystore) GetAuthKey(remove bool) ([]byte, error) {
	panic("implement me")
}

func (*testKeystore) Reset() {
	panic("implement me")
}

func TestDecryptGRPCService_Decrypt(t *testing.T) {
	ctx := context.Background()

	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	clientId := []byte("test client")
	data := []byte("data")
	keystore := &testKeystore{}
	service, err := NewDecryptGRPCService(keystore)
	if err != nil {
		t.Fatal(err)
	}

	// error if key not found by clientId
	response, err := service.Decrypt(ctx, &DecryptRequest{ClientId: clientId, Acrastruct: nil})
	if response != nil || err != ErrKeyNotFound {
		t.Fatal("expected key not found error")
	}

	// error if key not found by zone id
	response, err = service.Decrypt(ctx, &DecryptRequest{ZoneId: clientId, Acrastruct: nil})
	if response != nil || err != ErrKeyNotFound {
		t.Fatal("expected key not found error")
	}

	// set key
	keystore.PrivateKey = keypair.Private

	// test error on decyrption
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientId, Acrastruct: []byte("not acrastruct")})
	if err == nil {
		t.Fatal(err)
	}

	// test without zone
	acrastruct, err := acrawriter.CreateAcrastruct(data, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientId, Acrastruct: acrastruct})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Data, data) {
		t.Fatal("response data not equal to initial data")
	}

	// test with zone
	zoneId := clientId // use client id as zone id because no matter what to use
	acrastruct, err = acrawriter.CreateAcrastruct(data, keypair.Public, zoneId)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.Decrypt(ctx, &DecryptRequest{ZoneId: zoneId, Acrastruct: acrastruct})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Data, data) {
		t.Fatal("response data not equal to initial data")
	}

}
