/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package tests provides conformity test suite for KeyStore Backend API.
package tests

import (
	"testing"

	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
)

// NewBackend is a factory of backends under test.
type NewBackend func(t *testing.T) api.Backend

// TestBackend runs common backend tests.
func TestBackend(t *testing.T, newBackend NewBackend) {
	t.Run("TestGetPut", func(t *testing.T) {
		testGetPut(t, newBackend)
	})
	t.Run("TestSeparators", func(t *testing.T) {
		testSeparators(t, newBackend)
	})
	t.Run("TestRename", func(t *testing.T) {
		testRename(t, newBackend)
	})
	t.Run("TestRenameNX", func(t *testing.T) {
		testRenameNX(t, newBackend)
	})
	t.Run("TestLocking", func(t *testing.T) {
		testLocking(t, newBackend)
	})
}

func testGetPut(t *testing.T, newBackend NewBackend) {
	var err error
	b := newBackend(t)

	_, err = b.Get("missing")
	if err != api.ErrNotExist {
		t.Errorf("Get() for missing entry: %v", err)
	}

	err = b.Put("new", []byte("data"))
	if err != nil {
		t.Errorf("Put() for new entry: %v", err)
	}

	data, err := b.Get("new")
	if err != nil {
		t.Errorf("Get() for new entry: %v", err)
	}
	if string(data) != "data" {
		t.Errorf("Get() returned incorrect data: %v", string(data))
	}

	err = b.Put("new", []byte("another data"))
	if err != api.ErrExist {
		t.Errorf("Put() for new entry (again): %v", err)
	}
}

func testSeparators(t *testing.T, newBackend NewBackend) {
	var err error
	b := newBackend(t)

	err = b.Put("like/this", []byte("alpha"))
	if err != nil {
		t.Errorf("Put() with forward slashes: %v", err)
	}

	err = b.Put("and\\like\\that", []byte("bravo"))
	if err != nil {
		t.Errorf("Put() with backward slashes: %v", err)
	}

	data, err := b.Get("like\\this")
	if err != nil {
		t.Errorf("Get() with backward slashes: %v", err)
	}
	if string(data) != "alpha" {
		t.Errorf("Get() with backward slashes returned incorrect data: %v", string(data))
	}

	data, err = b.Get("and/like/that")
	if err != nil {
		t.Errorf("Get() with forward slashes: %v", err)
	}
	if string(data) != "bravo" {
		t.Errorf("Get() with forward slashes returned incorrect data: %v", string(data))
	}
}

func testRename(t *testing.T, newBackend NewBackend) {
	var err error
	b := newBackend(t)

	err = b.Rename("missing", "new")
	if err != api.ErrNotExist {
		t.Errorf("Rename() missing: %v", err)
	}

	err = b.Put("existing", []byte("data"))
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}
	err = b.Rename("existing", "new")
	if err != nil {
		t.Errorf("Rename() existing: %v", err)
	}

	err = b.Put("overwrite", []byte("this"))
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}
	err = b.Rename("new", "overwrite")
	if err != nil {
		t.Errorf("Rename() overwrite: %v", err)
	}
	data, err := b.Get("overwrite")
	if err != nil {
		t.Errorf("Get() overwrite: %v", err)
	}
	if string(data) != "data" {
		t.Errorf("Get() overwrite incorrect: %v", string(data))
	}

	err = b.Put("into itself", []byte("not lost"))
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}
	err = b.Rename("into itself", "into itself")
	if err != nil {
		t.Errorf("Rename() into itself: %v", err)
	}
	data, err = b.Get("into itself")
	if err != nil {
		t.Errorf("Get() into itself: %v", err)
	}
	if string(data) != "not lost" {
		t.Errorf("Get() into itself incorrect: %v", string(data))
	}
}

func testRenameNX(t *testing.T, newBackend NewBackend) {
	var err error
	b := newBackend(t)

	err = b.RenameNX("missing", "new")
	if err != api.ErrNotExist {
		t.Errorf("RenameNX() missing: %v", err)
	}

	err = b.Put("existing", []byte("data"))
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}
	err = b.RenameNX("existing", "new")
	if err != nil {
		t.Errorf("RenameNX() existing: %v", err)
	}

	err = b.Put("overwrite", []byte("this"))
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}
	err = b.RenameNX("new", "overwrite")
	if err != api.ErrExist {
		t.Errorf("RenameNX() overwrite: %v", err)
	}
	data, err := b.Get("overwrite")
	if err != nil {
		t.Errorf("Get() overwrite: %v", err)
	}
	if string(data) != "this" {
		t.Errorf("Get() overwrite incorrect: %v", string(data))
	}

	err = b.Put("into itself", []byte("not lost"))
	if err != nil {
		t.Fatalf("Put() failed: %v", err)
	}
	err = b.RenameNX("into itself", "into itself")
	if err != api.ErrExist {
		t.Errorf("RenameNX() into itself: %v", err)
	}
	data, err = b.Get("into itself")
	if err != nil {
		t.Errorf("Get() into itself: %v", err)
	}
	if string(data) != "not lost" {
		t.Errorf("Get() into itself incorrect: %v", string(data))
	}
}

func testLocking(t *testing.T, newBackend NewBackend) {
	t.Run("Exclusive", func(t *testing.T) {
		testLockingExclusive(t, newBackend)
	})
	t.Run("Shared", func(t *testing.T) {
		testLockingShared(t, newBackend)
	})
}

func testLockingExclusive(t *testing.T, newBackend NewBackend) {
	b := newBackend(t)

	// First, grab the lock.
	err := b.Lock()
	if err != nil {
		t.Fatalf("A: failed to grab exclusive lock: %v", err)
	}

	// Arrange for a second goroutine blocked on the same lock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := b.Lock()
		if err != nil {
			t.Fatalf("B: failed to grab exclusive lock: %v", err)
		}
		defer func() {
			err := b.Unlock()
			if err != nil {
				t.Fatalf("B: failed to release exclusive lock: %v", err)
			}
		}()

		// This should fail because the file already exists once we own the lock.
		err = b.Put("shared file", []byte("BBBBBB"))
		if err != api.ErrExist {
			t.Errorf("B: Put() incorrect result: %v", err)
		}

		// However, we can still write some other file and atomically update via rename.
		err = b.Put("other file", []byte("BBBBBB"))
		if err != nil {
			t.Fatalf("B: Put() failed: %v", err)
		}
		err = b.Rename("other file", "shared file")
		if err != nil {
			t.Fatalf("B: Rename() failed: %v", err)
		}
	}()

	// Updated shared file.
	err = b.Put("shared file", []byte("AAAAAA"))
	if err != nil {
		t.Errorf("A: Put() failed: %v", err)
	}

	// Release the lock. At some later point the other goroutine resumes.
	err = b.Unlock()
	if err != nil {
		t.Fatalf("A: failed to release exclusive lock: %v", err)
	}

	// Wait for the goroutine to complete, then check file content.
	<-done

	data, err := b.Get("shared file")
	if err != nil {
		t.Errorf("A: Get() failed: %v", err)
	}
	if string(data) != "BBBBBB" {
		t.Errorf("A: read unexpected data: %s", string(data))
	}
}

func testLockingShared(t *testing.T, newBackend NewBackend) {
	b := newBackend(t)

	// We can grab a shared lock multiple times in a row.
	err := b.RLock()
	if err != nil {
		t.Fatalf("A: failed to grab shared lock: %v", err)
	}
	err = b.RLock()
	if err != nil {
		t.Fatalf("A: failed to grab shared lock again: %v", err)
	}

	// We can also grab an exclusive lock (in a separate goroutine),
	// it will wait until all existing shared locks are released.
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := b.Lock()
		if err != nil {
			t.Fatalf("B: failed to grab exclusive lock: %v", err)
		}
		defer func() {
			err := b.Unlock()
			if err != nil {
				t.Fatalf("B: failed to release exclusive lock: %v", err)
			}
		}()

		err = b.Put("a file", []byte("tora-tora-tora!"))
		if err != nil {
			t.Fatalf("B: Put() failed: %v", err)
		}
	}()

	// The file does not exist yet, the goroutine is blocked.
	_, err = b.Get("a file")
	if err != api.ErrNotExist {
		t.Errorf("A: Get() seems to succeed: %v", err)
	}

	// And even after we have released the lock once, the file does not exist yet.
	err = b.RUnlock()
	if err != nil {
		t.Fatalf("A: failed to release shared lock: %v", err)
	}
	_, err = b.Get("a file")
	if err != api.ErrNotExist {
		t.Errorf("A: Get() seems to succeed (after Unlock x1): %v", err)
	}

	// We need to release the lock once more, then wait for the goroutine to complete,
	// and only then the file should be visible to us.
	err = b.RUnlock()
	if err != nil {
		t.Fatalf("A: failed to release shared lock: %v", err)
	}

	<-done

	data, err := b.Get("a file")
	if err != nil {
		t.Errorf("A: Get() failed (after Unlock x2): %v", err)
	}
	if string(data) != "tora-tora-tora!" {
		t.Errorf("A: Get() read incorrect content: %v", string(data))
	}
}
