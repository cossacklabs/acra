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

package backend

import (
	"sync"

	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
)

// InMemory backend is a dummy backend which keeps all data in memory.
// It is mostly useful for testing.
type InMemory struct {
	storage map[string][]byte
	lock    sync.RWMutex
}

// NewInMemory makes a new empty in-memory backend.
func NewInMemory() *InMemory {
	return &InMemory{
		storage: make(map[string][]byte),
	}
}

// Lock acquires an exclusive lock on the store.
func (m *InMemory) Lock() error {
	m.lock.Lock()
	return nil
}

// Unlock releases currently held exclusive lock.
func (m *InMemory) Unlock() error {
	m.lock.Unlock()
	return nil
}

// RLock acquires a shared lock on the store.
func (m *InMemory) RLock() error {
	m.lock.RLock()
	return nil
}

// RUnlock releases currently held shared lock.
func (m *InMemory) RUnlock() error {
	m.lock.RUnlock()
	return nil
}

// Close this backend instance, freeing any associated resources.
func (m *InMemory) Close() error {
	return nil
}

// Get data at given path.
func (m *InMemory) Get(path string) ([]byte, error) {
	path = pathSeparators.Replace(path)
	data, found := m.storage[path]
	if !found {
		return nil, api.ErrNotExist
	}
	return data, nil
}

// Put data at given path.
func (m *InMemory) Put(path string, data []byte) error {
	path = pathSeparators.Replace(path)
	_, found := m.storage[path]
	if found {
		return api.ErrExist
	}
	m.storage[path] = data
	return nil
}

// Rename oldpath into newpath atomically.
func (m *InMemory) Rename(oldpath, newpath string) error {
	oldpath = pathSeparators.Replace(oldpath)
	newpath = pathSeparators.Replace(newpath)
	data, found := m.storage[oldpath]
	if !found {
		return api.ErrNotExist
	}
	delete(m.storage, oldpath)
	m.storage[newpath] = data
	return nil
}

// RenameNX renames oldpath into newpath non-destructively.
func (m *InMemory) RenameNX(oldpath, newpath string) error {
	oldpath = pathSeparators.Replace(oldpath)
	newpath = pathSeparators.Replace(newpath)
	data, found := m.storage[oldpath]
	if !found {
		return api.ErrNotExist
	}
	_, found = m.storage[newpath]
	if found {
		return api.ErrExist
	}
	m.storage[newpath] = data
	delete(m.storage, oldpath)
	return nil
}
