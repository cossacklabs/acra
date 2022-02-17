package poison

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
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

func TestPoisonRecordProcessor_OnColumn(t *testing.T) {
	poisonKeypair, err := keys.New(keys.TypeEC)
	if err != nil {
		panic(err)
	}
	tkeystore := &testKeystore{PoisonKeypair: poisonKeypair}
	callbackStorage, callback := getTestPoisonCallbackStorageWithCallback()

	part1 := make([]byte, 1024)
	part2 := make([]byte, 1024)
	if _, err = rand.Read(part1); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(part2); err != nil {
		t.Fatal(err)
	}

	poisonRecord, err := CreatePoisonRecord(tkeystore, 1024)
	if err != nil {
		t.Fatal(err)
	}

	// poison record inside trash
	processor := RecordProcessor{keystore: tkeystore, callbacks: callbackStorage}
	_, _, err = processor.OnColumn(context.Background(), poisonRecord)
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if !callback.poisoned {
		t.Logf("test_data=%v\npoison_record=%v\npoison_public=%v\npoison_private=%v", base64.StdEncoding.EncodeToString(poisonRecord), base64.StdEncoding.EncodeToString(poisonRecord),
			base64.StdEncoding.EncodeToString(poisonKeypair.Public.Value), base64.StdEncoding.EncodeToString(poisonKeypair.Private.Value))
		t.Fatal("expected poisoned marker")
	}
	callback.poisoned = false

	// poison record inside trash
	testData := append(part1, append(poisonRecord, part2...)...)
	_, _, err = processor.OnColumn(context.Background(), testData)
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if !callback.poisoned {
		t.Logf("test_data=%v\npoison_record=%v\npoison_public=%v\npoison_private=%v", base64.StdEncoding.EncodeToString(testData), base64.StdEncoding.EncodeToString(poisonRecord),
			base64.StdEncoding.EncodeToString(poisonKeypair.Public.Value), base64.StdEncoding.EncodeToString(poisonKeypair.Private.Value))
		t.Fatal("expected poisoned marker")
	}
}
