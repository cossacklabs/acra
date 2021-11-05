/*
Copyright 2020, Cossack Labs Limited

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

package storage

import (
	"bytes"
	"testing"

	"github.com/cossacklabs/acra/pseudonymization/common"
)

func TestNewMemoryTokenStorage(t *testing.T) {
	store, err := NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(store)
	}

	type testcase struct {
		data    []byte
		context common.TokenContext
		id      []byte
	}
	testData := []testcase{
		{[]byte(`some data`), common.TokenContext{}, []byte(`some id0`)},
		{[]byte(`some data`), common.TokenContext{ClientID: []byte(`some context`)}, []byte(`some id1`)},
		{[]byte(`some data`), common.TokenContext{ClientID: []byte(`some context`), ZoneID: []byte(`some context2`)}, []byte(`some id2`)},
	}

	for _, tcase := range testData {
		value, err := store.Get(tcase.id, tcase.context)
		if err == nil {
			t.Fatal("expected error")
		}
		if value != nil {
			t.Fatal("unexpected value")
		}
		err = store.Save(tcase.id, tcase.context, tcase.data)
		if err != nil {
			t.Fatal("unexpected error on saving data")
		}
		value, err = store.Get(tcase.id, tcase.context)
		if err != nil {
			t.Fatal("unexpected error on Get operation")
		}
		if !bytes.Equal(value, tcase.data) {
			t.Fatal("expects that value should be the same")
		}
	}
}

func TestMemoryStorage(t *testing.T) {
	memoryStorage, err := NewMemoryTokenStorage()
	if err != nil {
		t.Fatal(err)
	}
	testStorage(memoryStorage, t)
}
