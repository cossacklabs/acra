package lru_cache

import (
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/golang/groupcache/lru"
)

// LRUCache implement keystore.Cache
type LRUCache struct {
	lru *lru.Cache
}

// clearCacheValue callback for lru.Cache that called on value remove operation
func clearCacheValue(key lru.Key, value interface{}) {
	switch value.(type) {
	case []byte:
		utils.FillSlice(byte(0), value.([]byte))
	case *keys.PrivateKey:
		utils.FillSlice(byte(0), value.(*keys.PrivateKey).Value)
	}
}

// NewLRUCacheKeystoreWrapper return new *LRUCache
func NewLRUCacheKeystoreWrapper(size int) (*LRUCache, error) {
	cache := &LRUCache{lru: lru.New(size)}
	cache.lru.OnEvicted = clearCacheValue
	return cache, nil
}

// Add value by keyID
func (cache *LRUCache) Add(keyID string, keyValue []byte) {
	cache.lru.Add(keyID, keyValue)
}

// Get value by keyID
func (cache *LRUCache) Get(keyID string) ([]byte, bool) {
	value, ok := cache.lru.Get(keyID)
	if ok {
		return value.([]byte), ok
	}
	return nil, ok
}

// Clear cache and remove all values with zeroing
func (cache *LRUCache) Clear() {
	cache.lru.Clear()
}
