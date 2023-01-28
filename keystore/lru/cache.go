/*
Copyright 2018, Cossack Labs Limited

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

// Package lru implements simple LRU cache used by Keystore. LRU cache stores in memory some amount of
// encrypted keys and removes less used keys upon adding new ones.
package lru

import (
	"sync"

	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/golang/groupcache/lru"

	"github.com/cossacklabs/acra/utils"
)

// Cache implement keystore.Cache
type Cache struct {
	lru   *lru.Cache
	mutex sync.RWMutex
}

// clearCacheValue callback for lru.Cache that called on value remove operation
func clearCacheValue(key lru.Key, value interface{}) {
	switch value := value.(type) {
	case []byte:
		utils.ZeroizeBytes(value)
	case *keys.PrivateKey:
		utils.ZeroizePrivateKey(value)
	}
}

// NewCacheKeystoreWrapper return new *Cache
func NewCacheKeystoreWrapper(size int) (*Cache, error) {
	cache := &Cache{lru: lru.New(size)}
	cache.lru.OnEvicted = clearCacheValue
	return cache, nil
}

// Add value by keyID
func (cache *Cache) Add(keyID string, keyValue []byte) {
	cache.mutex.Lock()
	cache.lru.Add(keyID, keyValue)
	cache.mutex.Unlock()
}

// Get value by keyID
func (cache *Cache) Get(keyID string) ([]byte, bool) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	value, ok := cache.lru.Get(keyID)
	if ok {
		return value.([]byte), ok
	}
	return nil, ok
}

// Clear cache and remove all values with zeroing
func (cache *Cache) Clear() {
	cache.mutex.Lock()
	cache.lru.Clear()
	cache.mutex.Unlock()
}
