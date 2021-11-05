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
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/cossacklabs/acra/pseudonymization/common"
)

func testStorage(storage common.TokenStorage, t *testing.T) {
	randValueSize := 100
	id := make([]byte, randValueSize)
	incorrectID := make([]byte, randValueSize)
	value1 := make([]byte, randValueSize)
	value2 := make([]byte, randValueSize)
	value3 := make([]byte, randValueSize)
	ctx1 := make([]byte, randValueSize)
	ctx2 := make([]byte, randValueSize)
	dataToGenerate := [][]byte{value1, value2, value3, ctx1, ctx2, id, incorrectID}
	for _, v := range dataToGenerate {
		n, err := rand.Read(v)
		if err != nil {
			t.Fatal(err)
		}
		if n != randValueSize {
			t.Fatal("generated not enough random value")
		}
	}

	beforeSave := time.Now()
	if err := storage.Save(id, common.TokenContext{}, value1); err != nil {
		t.Fatal(err)
	}
	afterSave := time.Now()

	metadata, err := storage.Stat(id, common.TokenContext{})
	if err != nil {
		t.Error(err)
	}
	if !timeBetween(beforeSave, metadata.Created, afterSave) {
		t.Error("incorrect creation time", metadata.Created)
		t.Logf("expected created after  %v", beforeSave)
		t.Logf("expected created before %v", afterSave)
	}
	if !metadata.Accessed.Equal(metadata.Created) {
		t.Error("last access time not equal to creation time")
		t.Log("actual  ", metadata.Accessed)
		t.Log("expected", metadata.Created)
	}

	// Stat()ing missing entries is detected and reported
	_, err = storage.Stat(incorrectID, common.TokenContext{})
	if err != common.ErrTokenNotFound {
		t.Error(err)
	}
	_, err = storage.Stat(id, common.TokenContext{ClientID: ctx1})
	if err != common.ErrTokenNotFound {
		t.Error(err)
	}

	// Attempt to save an already existing value is detected and reported
	if err := storage.Save(id, common.TokenContext{}, value1); err != common.ErrTokenExists {
		t.Fatal(err)
	}

	// Iterating through the entries should result in that one entry we've just saved
	foundIt := false
	err = storage.VisitMetadata(func(dataLength int, thisMetadata common.TokenMetadata) (common.TokenAction, error) {
		if dataLength == len(value1) && thisMetadata.Equal(metadata) {
			foundIt = true
		}
		return common.TokenContinue, nil
	})
	if err != nil {
		t.Error("VisitMetadata failed", err)
	}
	if !foundIt {
		t.Error("VisitMetadata did not return saved entry")
	}

	// If you return an error during iteration, it should be returned
	testError := errors.New("test error")
	err = storage.VisitMetadata(func(dataLength int, thisMetadata common.TokenMetadata) (common.TokenAction, error) {
		return common.TokenContinue, testError
	})
	if err != testError {
		t.Error("VisitMetadata does not forward error", err)
	}

	if err := storage.Save(id, common.TokenContext{ClientID: ctx1}, value2); err != nil {
		t.Fatal(err)
	}
	// You cannot save a different value under the same ID either.
	if err := storage.Save(id, common.TokenContext{ClientID: ctx1}, value3); err != common.ErrTokenExists {
		t.Fatal(err)
	}

	if err := storage.Save(id, common.TokenContext{ClientID: ctx2}, value3); err != nil {
		t.Fatal(err)
	}

	val1, err := storage.Get(id, common.TokenContext{})
	if err != nil {
		t.Fatal(err)
	}

	// Since the default granularity is 1 day, this Get() should not change the last access time.
	metadata1, err := storage.Stat(id, common.TokenContext{})
	if err != nil {
		t.Error(err)
	}
	if !metadata1.Accessed.Equal(metadata.Accessed) {
		t.Error("last access time should not change at the first Get()")
		t.Log("actual  ", metadata1.Accessed)
		t.Log("expected", metadata.Accessed)
	}

	// However, if the granularity is set to zero, every Get() should update the access time now.
	storage.SetAccessTimeGranularity(0)

	beforeGet := time.Now()
	_, err = storage.Get(id, common.TokenContext{})
	if err != nil {
		t.Fatal(err)
	}
	afterGet := time.Now()

	metadata2, err := storage.Stat(id, common.TokenContext{})
	if err != nil {
		t.Error(err)
	}

	// The modification time should be somewhere during the Get() call.
	// But the creation time should be unchaged.
	if !timeBetween(beforeGet, metadata2.Accessed, afterGet) {
		t.Error("incorrect last access time", metadata.Created)
		t.Logf("expected accessed after  %v", beforeGet)
		t.Logf("expected accessed before %v", afterGet)
	}
	if !metadata2.Created.Equal(metadata.Created) {
		t.Error("creation time should not change after Get()")
		t.Log("actual  ", metadata2.Created)
		t.Log("expected", metadata.Created)
	}

	val2, err := storage.Get(id, common.TokenContext{ClientID: ctx1})
	if err != nil {
		t.Fatal(err)
	}
	val3, err := storage.Get(id, common.TokenContext{ClientID: ctx2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(val1, value1) {
		t.Fatal("Fetched value not equal to saved value")
	}
	if !bytes.Equal(val2, value2) {
		t.Fatal("Fetched value not equal to saved value")
	}
	if !bytes.Equal(val3, value3) {
		t.Fatal("Fetched value not equal to saved value")
	}
	// Lookup for nonexistent values should fail.
	valIncorrect, err := storage.Get(incorrectID, common.TokenContext{})
	if err != common.ErrTokenNotFound || valIncorrect != nil {
		t.Fatal(err)
	}

	// If token entries are disabled, Get() requests should return a special error.
	err = storage.VisitMetadata(func(int, common.TokenMetadata) (common.TokenAction, error) {
		return common.TokenDisable, nil
	})
	if err != nil {
		t.Error("VisitMetadata failed to disable tokens", err)
	}
	_, err = storage.Get(id, common.TokenContext{})
	if err != common.ErrTokenDisabled {
		t.Error("tokens do not look disabled on Get()", err)
	}
	// If the tokens are enabled back, Get() should be fine again.
	err = storage.VisitMetadata(func(int, common.TokenMetadata) (common.TokenAction, error) {
		return common.TokenEnable, nil
	})
	if err != nil {
		t.Error("VisitMetadata failed to disable tokens", err)
	}
	_, err = storage.Get(id, common.TokenContext{})
	if err != nil {
		t.Error("failed to Get() a token after enabling it", err)
	}

	// However, if tokens are removed, they are no longer accessible.
	err = storage.VisitMetadata(func(int, common.TokenMetadata) (common.TokenAction, error) {
		return common.TokenRemove, nil
	})
	if err != nil {
		t.Error("VisitMetadata failed to remove tokens", err)
	}
	_, err = storage.Get(id, common.TokenContext{})
	if err != common.ErrTokenNotFound {
		t.Error("unexpected error from Get() after removal", err)
	}
	tokenCount := 0
	err = storage.VisitMetadata(func(int, common.TokenMetadata) (common.TokenAction, error) {
		tokenCount++
		return common.TokenContinue, nil
	})
	if err != nil {
		t.Error("VisitMetadata failed to iterate after removal", err)
	}
	if tokenCount != 0 {
		t.Error("storage is not empty after all tokens are removed:", tokenCount, "tokens are left")
	}
}

func timeBetween(b, t, a time.Time) bool {
	// Metadata stores times with precision of a second. Take that into account.
	const precision = time.Second
	b = b.Truncate(precision)
	t = t.Truncate(precision)
	a = a.Truncate(precision)
	// In most cases, b == t == a (as the tests are excuted quickly),
	// make sure to test b <= t <= a rather than b < t < a.
	return !(t.After(a) || t.Before(b))
}
