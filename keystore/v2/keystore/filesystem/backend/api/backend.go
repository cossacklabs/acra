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

// Package api defines abstract backend interface.
package api

import (
	"errors"
)

// PathSeparator used in key paths.
const PathSeparator = "/"

// Errors returned by filesystem.Backend:
var (
	ErrNotExist    = errors.New("key path does not exist")
	ErrExist       = errors.New("key path already exists")
	ErrInvalidPath = errors.New("invalid key path")
)

// Backend defines how KeyStore persists internal key data.
type Backend interface {
	// Get data at given path.
	// Returns ErrNotExist if path does not exist.
	Get(path string) ([]byte, error)
	// Put data at given path.
	// Returns ErrExist if path already exists.
	Put(path string, data []byte) error

	// Rename oldpath into newpath atomically.
	// Replaces newpath if it already exists.
	// Returns ErrNotExist if oldpath does not exist.
	Rename(oldpath, newpath string) error
	// Rename oldpath into newpath non-destructively.
	// Returns ErrExist if newpath already exists.
	// Returns ErrNotExist if oldpath does not exist.
	RenameNX(oldpath, newpath string) error

	// Lock acquires an exclusive lock on the store, suitable for writing.
	// This call blocks until the lock is acquired.
	// It can also deadlock if you already hold the lock.
	Lock() error
	// RLock acquires a shared lock on the store, suitable for reading.
	// This call blocks until the lock is acquired.
	RLock() error
	// Unlock releases the lock currently held by the process.
	// It is an error to call it without calling Lock() or Unlock() first.
	Unlock() error

	// Close this backend instance, freeing any associated resources.
	// This implicitly unlocks the store if any locks are held.
	Close() error
}
