package base_test

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"testing"
)

type TestCallback struct{ CallCount *int }

func (callback *TestCallback) Call() error {
	*callback.CallCount++
	return nil
}

func TestHasCallbacks(t *testing.T) {
	storage := base.NewPoisonCallbackStorage()
	if storage.HasCallbacks() {
		t.Fatal("storage shouldn't have any callbacks")
	}

	storage.AddCallback(&base.StopCallback{})
	if !storage.HasCallbacks() {
		t.Fatal("storage should have any callbacks")
	}
}

func TestCallCallbacks(t *testing.T) {
	storage := base.NewPoisonCallbackStorage()
	callCount := 0
	storage.AddCallback(&TestCallback{CallCount: &callCount})
	storage.AddCallback(&TestCallback{CallCount: &callCount})
	if err := storage.Call(); err != nil {
		t.Fatal("unexpected error")
	}
	if callCount != 2 {
		t.Fatal("incorrect call count")
	}
}
