package poison

import (
	"github.com/cossacklabs/themis/gothemis/keys"
)

type testKeystore struct {
	PoisonKeypair *keys.Keypair
}

func (keystore *testKeystore) GetPoisonSymmetricKeys() ([][]byte, error) {
	panic("implement me")
}

func (keystore *testKeystore) GetPoisonSymmetricKey() ([]byte, error) {
	panic("implement me")
}

func (keystore *testKeystore) GetPoisonKeyPair() (*keys.Keypair, error) {
	return keystore.PoisonKeypair, nil
}

func (keystore *testKeystore) GetPoisonPrivateKeys() ([]*keys.PrivateKey, error) {
	// make copy because caller may zeroize keys and expect that key always fetched from storage
	keyCopy := make([]byte, len(keystore.PoisonKeypair.Private.Value))
	copy(keyCopy, keystore.PoisonKeypair.Private.Value)
	return []*keys.PrivateKey{&keys.PrivateKey{Value: keyCopy}}, nil
}

type testCallback struct {
	*CallbackStorage
	poisoned bool
}

func (callback *testCallback) Call() error {
	callback.poisoned = true
	return nil
}

func getTestPoisonCallbackStorageWithCallback() (*CallbackStorage, *testCallback) {
	storage := NewCallbackStorage()
	callback := &testCallback{}
	storage.AddCallback(callback)
	return storage, callback
}
