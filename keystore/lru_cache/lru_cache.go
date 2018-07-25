package lru_cache

import (
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/golang/groupcache/lru"
)

type LRUCache struct {
	lru *lru.Cache
}

func clearCacheValue(key lru.Key, value interface{}) {
	switch value.(type) {
	case []byte:
		utils.FillSlice(byte(0), value.([]byte))
	case *keys.PrivateKey:
		utils.FillSlice(byte(0), value.(*keys.PrivateKey).Value)
	}
}

func NewLRUCacheKeystoreWrapper(size int) (*LRUCache, error) {
	cache := &LRUCache{lru: lru.New(size)}
	cache.lru.OnEvicted = clearCacheValue
	return cache, nil
}

func (cache *LRUCache) Add(keyId string, keyValue []byte) {
	cache.lru.Add(keyId, keyValue)
}

func (cache *LRUCache) Get(keyId string) ([]byte, bool) {
	value, ok := cache.lru.Get(keyId)
	if ok {
		return value.([]byte), ok
	}
	return nil, ok
}

func (cache *LRUCache) Clear() {
	cache.lru.Clear()
}
