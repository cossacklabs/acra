package grpc_api

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/themis/gothemis/keys"
	context "golang.org/x/net/context"
)

type testKeystore struct {
	PrivateKey *keys.PrivateKey
	PoisonKey  *keys.Keypair
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

func (keystore *testKeystore) GetPoisonKeyPair() (*keys.Keypair, error) {
	if keystore.PoisonKey != nil {
		return &keys.Keypair{Private: &keys.PrivateKey{Value: append([]byte{}, keystore.PoisonKey.Private.Value...)}, Public: store.PoisonKey.Public}, nil
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

func (callback *poisonCallback) Call() error {
	callback.Called = true
	return nil
}

func TestDecryptGRPCService_Decrypt(t *testing.T) {
	ctx := context.Background()

	keypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	clientID := []byte("test client")
	data := []byte("data")
	keystore := &testKeystore{}
	poisonKeypair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	keystore.PoisonKey = poisonKeypair

	poisonCallbacks := base.NewPoisonCallbackStorage()
	translatorData := &common.TranslatorData{PoisonRecordCallbacks: poisonCallbacks, Keystorage: keystore, CheckPoisonRecords: true}
	service, err := NewDecryptGRPCService(translatorData)
	if err != nil {
		t.Fatal(err)
	}

	// check that clientID is required
	response, err := service.Decrypt(ctx, &DecryptRequest{ClientId: nil, Acrastruct: nil})
	if response != nil || err != ErrClientIDRequired {
		t.Fatal("expected key not found error")
	}

	// error if key not found by clientID
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientID, Acrastruct: nil})
	if response != nil || err != ErrCantDecrypt {
		t.Fatal("expected key not found error")
	}

	// error if key not found by zone id
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientID, ZoneId: clientID, Acrastruct: nil})
	if response != nil || err != ErrCantDecrypt {
		t.Fatal("expected key not found error")
	}

	// set key
	keystore.PrivateKey = keypair.Private

	// test error on decyrption
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientID, Acrastruct: []byte("not acrastruct")})
	if err == nil {
		t.Fatal(err)
	}

	// test without zone
	acrastruct, err := acrawriter.CreateAcrastruct(data, keypair.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientID, Acrastruct: acrastruct})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Data, data) {
		t.Fatal("response data not equal to initial data")
	}

	// test with zone
	zoneID := clientID // use client id as zone id because no matter what to use
	acrastruct, err = acrawriter.CreateAcrastruct(data, keypair.Public, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientID, ZoneId: zoneID, Acrastruct: acrastruct})
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
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientID, ZoneId: zoneID, Acrastruct: poisonRecord})
	if err == nil {
		t.Fatal(err)
	}
	if !callback.Called {
		t.Fatal("Poison record callback wasn't called")
	}

	// check that we can turn off poison record detection
	translatorData.CheckPoisonRecords = false
	callback.Called = false // reset
	response, err = service.Decrypt(ctx, &DecryptRequest{ClientId: clientID, ZoneId: zoneID, Acrastruct: poisonRecord})
	if err != ErrCantDecrypt {
		t.Fatal(err)
	}
	if callback.Called {
		t.Fatal("Poison record callback was called")
	}
}
