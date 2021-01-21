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
	"golang.org/x/net/context"
)

type testKeystore struct {
	PoisonKey         *keys.Keypair
	EncryptionKeypair *keys.Keypair
	UsedID            []byte
}

func (keystore *testKeystore) GetZonePrivateKeys(id []byte) ([]*keys.PrivateKey, error) {
	keystore.UsedID = id
	if keystore.EncryptionKeypair != nil {
		return []*keys.PrivateKey{{Value: append([]byte{}, keystore.EncryptionKeypair.Private.Value...)}}, nil
	}
	return nil, ErrKeyNotFound
}

func (keystore *testKeystore) GetServerDecryptionPrivateKeys(id []byte) ([]*keys.PrivateKey, error) {
	if keystore.EncryptionKeypair != nil {
		return []*keys.PrivateKey{{Value: append([]byte{}, keystore.EncryptionKeypair.Private.Value...)}}, nil
	}
	return nil, ErrKeyNotFound
}

func (keystore *testKeystore) RotateZoneKey(zoneID []byte) ([]byte, error) {
	panic("implement me")
}

func (keystore *testKeystore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	keystore.UsedID = id
	return keystore.EncryptionKeypair.Private, nil
}

func (keystore *testKeystore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	keystore.UsedID = id
	return keystore.EncryptionKeypair.Public, nil
}

func (*testKeystore) SaveDataEncryptionKeys(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*testKeystore) SaveTranslatorKeypair(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*testKeystore) SaveServerKeypair(id []byte, keypair *keys.Keypair) error { panic("implement me") }
func (*testKeystore) SaveConnectorKeypair(id []byte, keypair *keys.Keypair) error {
	panic("implement me")
}
func (*testKeystore) SaveZoneKeypair(id []byte, keypair *keys.Keypair) error { panic("implement me") }

var ErrKeyNotFound = errors.New("some error")

func (keystore *testKeystore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	if keystore.EncryptionKeypair != nil {
		return &keys.PrivateKey{Value: append([]byte{}, keystore.EncryptionKeypair.Private.Value...)}, nil
	}
	return nil, ErrKeyNotFound

}

func (*testKeystore) HasZonePrivateKey(id []byte) bool {
	panic("implement me")
}

func (keystore *testKeystore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	if keystore.EncryptionKeypair != nil {
		return &keys.PrivateKey{Value: append([]byte{}, keystore.EncryptionKeypair.Private.Value...)}, nil
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
		return &keys.Keypair{Private: &keys.PrivateKey{Value: append([]byte{}, keystore.PoisonKey.Private.Value...)}, Public: keystore.PoisonKey.Public}, nil
	}
	return nil, nil
}

func (keystore *testKeystore) GetPoisonPrivateKeys() ([]*keys.PrivateKey, error) {
	keypair, err := keystore.GetPoisonKeyPair()
	if err != nil || keypair == nil {
		return nil, err
	}
	return []*keys.PrivateKey{keypair.Private}, nil
}

func (*testKeystore) GetAuthKey(remove bool) ([]byte, error) { panic("implement me") }

func (*testKeystore) Reset() { panic("implement me") }

func (keystore *testKeystore) GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error) {
	if keystore.EncryptionKeypair != nil {
		return &keys.PublicKey{Value: keystore.EncryptionKeypair.Public.Value}, nil
	}
	return nil, ErrKeyNotFound
}

func (keystore *testKeystore) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	keystore.UsedID = clientID
	if keystore.EncryptionKeypair != nil {
		return &keys.PublicKey{Value: keystore.EncryptionKeypair.Public.Value}, nil
	}
	return nil, ErrKeyNotFound
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

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	clientID := []byte("test client")
	data := []byte("data")
	keystore := &testKeystore{}
	poisonKeypair, err := keys.New(keys.TypeEC)
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
	keystore.EncryptionKeypair = keypair

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

func TestDecryptGRPCService_Encrypt(t *testing.T) {
	ctx := context.Background()
	clientID := []byte("test client")
	data := []byte("data")
	keystore := &testKeystore{}
	encryptionKey, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}
	keystore.EncryptionKeypair = encryptionKey

	translatorData := &common.TranslatorData{Keystorage: keystore, CheckPoisonRecords: false}
	service, err := NewDecryptGRPCService(translatorData)
	if err != nil {
		t.Fatal(err)
	}

	// encrypt with client id
	response, err := service.Encrypt(ctx, &EncryptRequest{Data: data, ClientId: clientID})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := base.DecryptAcrastruct(response.Acrastruct, encryptionKey.Private, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatal("Incorrect encryption/decryption with client id")
	}

	// encrypt with zone id
	zoneID := []byte("some zone")
	response, err = service.Encrypt(ctx, &EncryptRequest{Data: data, ClientId: clientID, ZoneId: zoneID})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = base.DecryptAcrastruct(response.Acrastruct, encryptionKey.Private, zoneID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatal("Incorrect encryption/decryption with zone id")
	}
}
