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
	"encoding/base64"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend/api"
	"github.com/go-redis/redis/v7"
	log "github.com/sirupsen/logrus"
)

const redisSubsystemName = "redis-backend"

// ErrLockTimeout errors returned by RedisBackend:
var ErrLockTimeout = errors.New("timed out while waiting for lock")

// RedisBackend keeps key data in Redis database.
type RedisBackend struct {
	redis   *redis.Client
	rootDir string
	log     *log.Entry
}

// RedisConfig defines Redis keystore configuration.
type RedisConfig struct {
	Options *redis.Options
	RootDir string
}

const (
	lockKey      = ".lock"
	versionKey   = "version"
	noExpiration = time.Duration(0)

	lockToken       = "locked"
	maxLockDuration = 10 * time.Second
)

func openRedisConnection(config *RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(config.Options)
	err := client.Ping().Err()
	if err != nil {
		return nil, err
	}
	return client, err
}

// CreateRedisBackend opens a Redis backend at given root path.
// The root directory will be created if it does not exist.
func CreateRedisBackend(config *RedisConfig) (*RedisBackend, error) {
	log := log.WithFields(log.Fields{
		"service":   serviceName,
		"subsystem": redisSubsystemName,
	})
	client, err := openRedisConnection(config)
	if err != nil {
		log.WithError(err).Debug("Failed to connect to Redis")
		return nil, err
	}
	err = ensureRedisVersionKey(client, config)
	if err != nil {
		log.WithError(err).Debug("Cannot create version key")
		return nil, err
	}
	return &RedisBackend{redis: client, rootDir: config.RootDir, log: log}, nil
}

// OpenRedisBackend opens a Redis backend at given root path.
func OpenRedisBackend(config *RedisConfig) (*RedisBackend, error) {
	log := log.WithFields(log.Fields{
		"service":   serviceName,
		"subsystem": redisSubsystemName,
	})
	client, err := openRedisConnection(config)
	if err != nil {
		log.WithError(err).Debug("Failed to connect to Redis")
		return nil, err
	}
	err = checkRedisVersionKey(client, config)
	if err != nil {
		log.WithError(err).Debug("Keystore version key not valid")
		return nil, err
	}
	return &RedisBackend{redis: client, rootDir: config.RootDir, log: log}, nil
}

func redisVersionKey(config *RedisConfig) string {
	return filepath.Join(config.RootDir, versionKey)
}

func checkRedisVersionKey(client *redis.Client, config *RedisConfig) error {
	content, err := client.Get(redisVersionKey(config)).Result()
	if err != nil {
		return err
	}
	if content != versionString {
		return ErrInvalidVersion
	}
	return nil
}

func ensureRedisVersionKey(client *redis.Client, config *RedisConfig) error {
	err := checkRedisVersionKey(client, config)
	// If the keystore already contains a valid versio key then we're good.
	if err == nil {
		return nil
	}
	// If the key does not exist, this must be a newly initialized keystore.
	// Create a key if that's the case, and return any other errors otherwise.
	if err == redis.Nil {
		return createRedisVersionKey(client, config)
	}
	return err
}

func createRedisVersionKey(client *redis.Client, config *RedisConfig) error {
	return client.Set(redisVersionKey(config), versionString, noExpiration).Err()
}

func (b *RedisBackend) keyPath(path string) string {
	return filepath.Join(b.rootDir, pathSeparators.Replace(path))
}

// Close this backend instance, freeing any associated resources.
func (b *RedisBackend) Close() error {
	err := b.redis.Close()
	if err != nil {
		b.log.WithError(err).Warn("Failed to close Redis connection")
	}
	return err
}

// See https://redis.io/commands/set#patterns for how we implement basic locking.
// This is exclusive-only lock. Implementing shared locks is harder and it's not
// critical for performance.

// Lock acquires an exclusive lock on the store.
func (b *RedisBackend) Lock() error {
	lock := b.keyPath(lockKey)
	deadline := time.Now().Add(maxLockDuration)
	for time.Now().Before(deadline) {
		locked, err := b.redis.SetNX(lock, lockToken, maxLockDuration).Result()
		if err != nil {
			b.log.WithError(err).Debug("Failed to acquire Redis lock")
			return err
		}
		// If we have set the key, we have acquired the lock. Otherwise, keep waiting.
		if locked {
			return nil
		}
	}
	return ErrLockTimeout
}

// Unlock releases currently held exclusive lock.
func (b *RedisBackend) Unlock() error {
	lock := b.keyPath(lockKey)
	released, err := b.redis.Del(lock).Result()
	if err != nil {
		b.log.WithError(err).Debug("Failed to release Redis lock")
		return err
	}
	if released != 1 {
		b.log.Warn("Releasing expired Redis lock")
	}
	return nil
}

// RLock acquires a shared lock on the store.
func (b *RedisBackend) RLock() error {
	return b.Lock()
}

// RUnlock releases currently held shared lock.
func (b *RedisBackend) RUnlock() error {
	return b.Unlock()
}

// Get data at given path.
func (b *RedisBackend) Get(path string) ([]byte, error) {
	path = b.keyPath(path)
	data, err := b.redis.Get(path).Result()
	if err != nil {
		b.log.WithError(err).WithField("path", path).Debug("Failed to read key data")
		if err == redis.Nil {
			err = api.ErrNotExist
		}
		return nil, err
	}
	return base64.StdEncoding.DecodeString(data)
}

// Put data at given path.
func (b *RedisBackend) Put(path string, data []byte) error {
	path = b.keyPath(path)
	base64 := base64.StdEncoding.EncodeToString(data)
	// Put must fail if there is already a key at given path.
	set, err := b.redis.SetNX(path, base64, noExpiration).Result()
	if err != nil || !set {
		if !set && err == nil {
			err = api.ErrExist
		}
		b.log.WithError(err).WithField("path", path).Debug("Failed to write key data")
	}
	return err
}

// ListAll enumerates all paths currently stored.
// The paths are returned in lexicographical order.
func (b *RedisBackend) ListAll() ([]string, error) {
	const defaultCount = 10
	keys := make([]string, 0, defaultCount)
	// First, enumerate all available keys in the root directory.
	var cursor uint64
	for {
		nextKeys, nextCursor, err := b.redis.Scan(cursor, b.rootDir+"/*", defaultCount).Result()
		if err != nil {
			return nil, err
		}
		// Trim the root directory from paths, it's implicit.
		// While we're here, filter out special keys as well.
		for _, key := range nextKeys {
			key = strings.TrimPrefix(key, b.rootDir+"/")
			if key == versionKey || key == lockKey {
				continue
			}
			keys = append(keys, key)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Rename oldpath into newpath.
func (b *RedisBackend) Rename(oldpath, newpath string) error {
	oldpath = b.keyPath(oldpath)
	newpath = b.keyPath(newpath)
	err := b.redis.Rename(oldpath, newpath).Err()
	if err != nil {
		// Unfortunately, there is no error constant :(
		if strings.HasSuffix(err.Error(), "no such key") {
			err = api.ErrNotExist
		}
		b.log.WithError(err).WithFields(log.Fields{"src": oldpath, "dst": newpath}).
			Debug("Failed to rename key")
	}
	return err
}

// RenameNX renames oldpath into newpath non-destructively.
func (b *RedisBackend) RenameNX(oldpath, newpath string) error {
	oldpath = b.keyPath(oldpath)
	newpath = b.keyPath(newpath)
	renamed, err := b.redis.RenameNX(oldpath, newpath).Result()
	if err != nil || !renamed {
		// Unfortunately, there is no error constant :(
		if err != nil && strings.HasSuffix(err.Error(), "no such key") {
			err = api.ErrNotExist
		} else if !renamed {
			err = api.ErrExist
		}
		b.log.WithError(err).WithFields(log.Fields{"src": oldpath, "dst": newpath}).
			Debug("Failed to rename key (exclusive)")
	}
	return err
}
