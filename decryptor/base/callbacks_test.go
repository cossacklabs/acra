/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
