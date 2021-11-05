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
	"encoding/hex"
	"sync"
	"time"

	"github.com/cossacklabs/acra/pseudonymization/common"
)

// MemoryTokenStorage implements TokenStorage and store data in process memory
type MemoryTokenStorage struct {
	data  map[string]map[string]*memoryTokenData
	mutex *sync.RWMutex

	accessGranularity time.Duration
}

type memoryTokenData struct {
	data     []byte
	metadata common.TokenMetadata
}

// NewMemoryTokenStorage return new memory token storage
func NewMemoryTokenStorage() (*MemoryTokenStorage, error) {
	return &MemoryTokenStorage{
		data:  make(map[string]map[string]*memoryTokenData),
		mutex: &sync.RWMutex{},

		accessGranularity: common.DefaultAccessTimeGranularity,
	}, nil
}

// Save data with defined id and context
func (m *MemoryTokenStorage) Save(id []byte, context common.TokenContext, data []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	idStr := hex.EncodeToString(id)
	ctx := common.AggregateTokenContextToBytes(context)
	ctxStr := hex.EncodeToString(ctx)
	ctxMap, ok := m.data[ctxStr]
	if !ok {
		ctxMap = make(map[string]*memoryTokenData)
		m.data[ctxStr] = ctxMap
	}
	_, ok = ctxMap[idStr]
	if ok {
		return common.ErrTokenExists
	}
	ctxMap[idStr] = &memoryTokenData{data, common.NewTokenMetadata()}
	return nil
}

// Get data with defined id and context
func (m *MemoryTokenStorage) Get(id []byte, context common.TokenContext) ([]byte, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	idStr := hex.EncodeToString(id)
	ctx := common.AggregateTokenContextToBytes(context)
	ctxStr := hex.EncodeToString(ctx)
	ctxMap, ok := m.data[ctxStr]
	if !ok {
		return nil, common.ErrTokenNotFound
	}
	value, ok := ctxMap[idStr]
	if !ok {
		return nil, common.ErrTokenNotFound
	}
	// If the token is disabled, pretend that it's not there. (Don't update last access time either.)
	if value.metadata.Disabled {
		return nil, common.ErrTokenDisabled
	}
	// Keep last access time updated, but don't update it more often than specified granularity.
	now := time.Now().UTC()
	if value.metadata.AccessedBefore(now, m.accessGranularity) {
		value.metadata.Accessed = now
	}
	return value.data, nil
}

// Stat returns metadata of a token entry.
func (m *MemoryTokenStorage) Stat(id []byte, context common.TokenContext) (common.TokenMetadata, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	idStr := hex.EncodeToString(id)
	ctx := common.AggregateTokenContextToBytes(context)
	ctxStr := hex.EncodeToString(ctx)
	ctxMap, ok := m.data[ctxStr]
	if !ok {
		return common.TokenMetadata{}, common.ErrTokenNotFound
	}
	value, ok := ctxMap[idStr]
	if !ok {
		return common.TokenMetadata{}, common.ErrTokenNotFound
	}
	return value.metadata, nil
}

// SetAccessTimeGranularity sets access time granularity.
func (m *MemoryTokenStorage) SetAccessTimeGranularity(granularity time.Duration) error {
	m.accessGranularity = granularity
	return nil
}

// VisitMetadata over token metadata in the storage.
func (m *MemoryTokenStorage) VisitMetadata(cb func(dataLength int, metadata common.TokenMetadata) (common.TokenAction, error)) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, ctxMap := range m.data {
		for id, token := range ctxMap {
			action, err := cb(len(token.data), token.metadata)
			if err != nil {
				return err
			}
			switch action {
			case common.TokenDisable:
				token.metadata.Disabled = true
			case common.TokenEnable:
				token.metadata.Disabled = false
			case common.TokenRemove:
				delete(ctxMap, id)
			}
		}
	}
	return nil
}
