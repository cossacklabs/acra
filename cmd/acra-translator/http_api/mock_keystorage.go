package http_api

import (
	"errors"
	"github.com/cossacklabs/themis/gothemis/keys"
)

type testKeystore struct {
	PrivateKey    *keys.PrivateKey
	PoisonKeyPair *keys.Keypair
}

func (*testKeystore) GetPrivateKey(id []byte) (*keys.PrivateKey, error) {
	panic("implement me")
}

func (*testKeystore) GetPeerPublicKey(id []byte) (*keys.PublicKey, error) {
	panic("implement me")
}

// ErrKeyNotFound indicates error when decryption key is not found.
var ErrKeyNotFound = errors.New("some error")

func (keystore *testKeystore) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	if keystore.PrivateKey != nil {
		copied := make([]byte, len(keystore.PrivateKey.Value))
		copy(copied, keystore.PrivateKey.Value)
		return &keys.PrivateKey{Value: copied}, nil
	}
	return nil, ErrKeyNotFound

}

func (*testKeystore) HasZonePrivateKey(id []byte) bool {
	panic("implement me")
}

func (keystore *testKeystore) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	if keystore.PrivateKey != nil {
		copied := make([]byte, len(keystore.PrivateKey.Value))
		copy(copied, keystore.PrivateKey.Value)
		return &keys.PrivateKey{Value: copied}, nil
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
	// if explicitly set for tests
	if keystore.PoisonKeyPair != nil {
		// copy private key because it should be zeroed after that
		privateKey := &keys.PrivateKey{Value: append([]byte{}, keystore.PoisonKeyPair.Private.Value...)}
		return &keys.Keypair{Private: privateKey, Public: keystore.PoisonKeyPair.Public}, nil
	}
	// we no matter what the key
	return keys.New(keys.KEYTYPE_EC)
}

func (*testKeystore) GetAuthKey(remove bool) ([]byte, error) {
	panic("implement me")
}

func (*testKeystore) Reset() {
	panic("implement me")
}
