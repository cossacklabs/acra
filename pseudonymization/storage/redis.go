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
	"crypto/tls"
	"encoding/hex"
	"time"

	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/go-redis/redis/v7"
)

// NewRedisClient return new redis client
func NewRedisClient(hostport, password string, db int, tlsConfig *tls.Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:      hostport,
		Password:  password, // no password set
		DB:        db,       // use default DB
		TLSConfig: tlsConfig,
	})

	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}
	return client, nil
}

// RedisStorage implements TokenStorage using Redis as storage backend
type RedisStorage struct {
	client *redis.Client

	accessGranularity time.Duration
}

const noExpiration = 0

// NewRedisStorage return new redis storage for tokens using client
func NewRedisStorage(client *redis.Client) (*RedisStorage, error) {
	return &RedisStorage{client, common.DefaultAccessTimeGranularity}, nil
}

const redisTokensPrefix = "tokens/"

func (m *RedisStorage) generateKey(id []byte, context common.TokenContext) string {
	contextKey := hex.EncodeToString(common.AggregateTokenContextToBytes(context))
	idKey := hex.EncodeToString(id)
	return redisTokensPrefix + contextKey + "/" + idKey
}

// Save data with defined id and context
func (m *RedisStorage) Save(id []byte, context common.TokenContext, data []byte) error {
	key := m.generateKey(id, context)
	value := common.EmbedMetadata(data, common.NewTokenMetadata())
	valueStr := hex.EncodeToString(value)
	set, err := m.client.SetNX(key, valueStr, noExpiration).Result()
	if err != nil {
		return err
	}
	if !set {
		return common.ErrTokenExists
	}
	return nil
}

// Get data with defined id and context
func (m *RedisStorage) Get(id []byte, context common.TokenContext) ([]byte, error) {
	key := m.generateKey(id, context)
	valueStr, err := m.client.Get(key).Result()
	if err == redis.Nil {
		return nil, common.ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	value, err := hex.DecodeString(valueStr)
	if err != nil {
		return nil, err
	}
	data, metadata, err := common.ExtractMetadata(value)
	if err != nil {
		return nil, err
	}
	// If the token is disabled, pretend that it's not there. (Don't update last access time either.)
	if metadata.Disabled {
		return nil, common.ErrTokenDisabled
	}
	// Keep last access time updated, but don't update it more often than specified granularity.
	now := time.Now().UTC()
	if metadata.AccessedBefore(now, m.accessGranularity) {
		metadata.Accessed = now
		value := common.EmbedMetadata(data, metadata)
		valueStr := hex.EncodeToString(value)
		_, err := m.client.SetXX(key, valueStr, noExpiration).Result()
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// Stat returns metadata of a token entry.
func (m *RedisStorage) Stat(id []byte, context common.TokenContext) (common.TokenMetadata, error) {
	valueStr, err := m.client.Get(m.generateKey(id, context)).Result()
	if err == redis.Nil {
		return common.TokenMetadata{}, common.ErrTokenNotFound
	}
	if err != nil {
		return common.TokenMetadata{}, err
	}
	value, err := hex.DecodeString(valueStr)
	if err != nil {
		return common.TokenMetadata{}, err
	}
	_, metadata, err := common.ExtractMetadata(value)
	if err != nil {
		return common.TokenMetadata{}, err
	}
	return metadata, nil
}

// SetAccessTimeGranularity sets access time granularity.
func (m *RedisStorage) SetAccessTimeGranularity(granularity time.Duration) error {
	m.accessGranularity = granularity
	return nil
}

// How many keys to retrieve from Redis at once (a suggestion to Redis)
const redisDefaultKeyCount = 10

// VisitMetadata over token metadata in the storage.
func (m *RedisStorage) VisitMetadata(cb func(dataLength int, metadata common.TokenMetadata) (common.TokenAction, error)) error {
	var cursor uint64
	for {
		nextKeys, nextCursor, err := m.client.Scan(cursor, redisTokensPrefix+"*", redisDefaultKeyCount).Result()
		if err != nil {
			return err
		}
		// MGET requires non-empty list of keys, and if there is nothing to iterate through, don't make unnecessary requests.
		// However, note that SCAN may return empty key sets during the iteration. It's not over until the cursor is zero.
		if len(nextKeys) > 0 {
			valueStrings, err := m.client.MGet(nextKeys...).Result()
			if err != nil {
				return err
			}
			var updates []string
			var removals []string
			for i, valueStr := range valueStrings {
				// MGET may return nil values if keys have been removed during iteration. Just skip them.
				if valueStr == nil {
					continue
				}
				value, err := hex.DecodeString(valueStr.(string))
				if err != nil {
					return err
				}
				data, metadata, err := common.ExtractMetadata(value)
				if err != nil {
					return err
				}
				action, err := cb(len(data), metadata)
				if err != nil {
					return err
				}
				switch action {
				case common.TokenDisable:
					if !metadata.Disabled {
						metadata.Disabled = true
						value := common.EmbedMetadata(data, metadata)
						valueStr := hex.EncodeToString(value)
						updates = append(updates, nextKeys[i], valueStr)
					}
				case common.TokenEnable:
					if metadata.Disabled {
						metadata.Disabled = false
						value := common.EmbedMetadata(data, metadata)
						valueStr := hex.EncodeToString(value)
						updates = append(updates, nextKeys[i], valueStr)
					}
				case common.TokenRemove:
					removals = append(removals, nextKeys[i])
				}
			}
			// If there are any pending metadata updates, apply them now (atomically).
			if len(updates) > 0 {
				_, err := m.client.MSet(updates).Result()
				if err != nil {
					return err
				}
			}
			if len(removals) > 0 {
				_, err := m.client.Del(removals...).Result()
				if err != nil {
					return err
				}
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}
