package grpc_api

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/themis/gothemis/keys"
	context "golang.org/x/net/context"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/poison"
)

type testKeystore struct {
	PrivateKey *keys.PrivateKey
	PoisonKey *keys.Keypair
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

func (*testKeystore) GenerateTranslatorKeys(id []byte) error {
	panic("implement me")
}

func (*testKeystore) GenerateDataEncryptionKeys(id []byte) error {
	panic("implement me")
}

func (store *testKeystore) GetPoisonKeyPair() (*keys.Keypair, error) {
	if store.PoisonKey != nil {
		return &keys.Keypair{Private: &keys.PrivateKey{Value:append([]byte{}, store.PoisonKey.Private.Value...)}, Public: store.PoisonKey.Public}, nil
	}
	return nil, nil
}

func (*testKeystore) GetAuthKey(remove bool) ([]byte, error) {
	panic("implement me")
}

func (*testKeystore) Reset() {
	panic("implement me")
}

type poisonCallback struct {
	Called bool
}
func (callback *poisonCallback) Call() error{
	callback.Called = true
	return nil
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
	poisonKeypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	keystore.PoisonKey = poisonKeypair

	poisonCallbacks := base.NewPoisonCallbackStorage()
	service, err := NewDecryptGRPCService(keystore, poisonCallbacks)
	if err != nil {
		t.Fatal(err)
	}

	// check that clientId is required
	response, err := service.Decrypt(ctx, &DecryptRequest{ClientId: nil, Acrastruct: nil})
	if response != nil || err != ErrClientIdRequired {
		t.Fatal("expected key not found error")
	}

	// error if key not found by clientId
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientId, Acrastruct: nil})
	if response != nil || err != ErrCantDecrypt {
		t.Fatal("expected key not found error")
	}

	// error if key not found by zone id
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientId, ZoneId: clientId, Acrastruct: nil})
	if response != nil || err != ErrCantDecrypt {
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
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientId, ZoneId: zoneId, Acrastruct: acrastruct})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Data, data) {
		t.Fatal("response data not equal to initial data")
	}

	poisonRecord, err := poison.CreatePoisonRecord(keystore, 100)
	if err != nil {
		t.Fatal(err)
	}
	callback := &poisonCallback{}
	poisonCallbacks.AddCallback(callback)
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientId, ZoneId: zoneId, Acrastruct: poisonRecord})
	if err == nil {
		t.Fatal(err)
	}
	if !callback.Called {
		t.Fatal("Poison record callback wasn't called")
	}
}
