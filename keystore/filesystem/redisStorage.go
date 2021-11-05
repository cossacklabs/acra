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

package filesystem

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis/v7"
)

// RedisStorage provides a storage backend that keeps key in Redis.
type RedisStorage struct {
	redisStorage
}

type redisStorage struct {
	client *redis.Client
}

// NewRedisStorage returns a new Redis backend.
func NewRedisStorage(address string, password string, db int, tls *tls.Config) (Storage, error) {
	client := redis.NewClient(&redis.Options{
		Addr:      address,
		Password:  password,
		DB:        db,
		TLSConfig: tls,
	})
	err := client.Ping().Err()
	if err != nil {
		return nil, err
	}
	return &RedisStorage{redisStorage: redisStorage{client}}, nil
}

// Storage users expect errors compatible with os.IsNotExist() and os.IsExist()
func fixupENOENT(err error) error {
	if err == redis.Nil {
		return os.ErrNotExist
	}
	return err
}

func fixupEEXIST(err error) error {
	if err == redis.Nil {
		return os.ErrExist
	}
	return err
}

type redisFileInfo struct {
	name  string
	size  int64
	isDir bool
}

// These values are acceptable for private keys and their directories
const (
	redisFileMode = os.FileMode(0600)
	redisDirMode  = os.FileMode(0700) | os.ModeDir
)

func (fi *redisFileInfo) Name() string {
	return fi.name
}

func (fi *redisFileInfo) Size() int64 {
	return fi.size
}

func (fi *redisFileInfo) Mode() os.FileMode {
	if fi.isDir {
		return redisDirMode
	}
	return redisFileMode
}

func (fi *redisFileInfo) ModTime() time.Time {
	// Redis does not record modification time, we don't do it either
	return time.Time{}
}

func (fi *redisFileInfo) IsDir() bool {
	return fi.isDir
}

func (fi *redisFileInfo) Sys() interface{} {
	return nil
}

const defaultCount = 10

func (r *redisStorage) Stat(path string) (os.FileInfo, error) {
	count, err := r.client.Exists(path).Result()
	if err != nil {
		return nil, err
	}
	// If a key exists then it's a 'file'. Query its length.
	if count > 0 {
		len, err := r.client.StrLen(path).Result()
		if err != nil {
			return nil, err
		}
		// base64 returns approximate length which may be slightly bigger than necessary,
		// but we don't really care about accuracy. We only need to know whether it's zero
		// or non-zero as some os.FileInfo users depend on that.
		// Also, this will overflow for keys larger than "int", but we shouldn't have such.
		len = int64(base64.StdEncoding.DecodedLen(int(len)))
		return &redisFileInfo{
			name:  path,
			size:  len,
			isDir: false,
		}, nil
	}
	// If a key does not exist at given path then it might be a directory
	// if the path is a prefix of some existing key.
	keys, _, err := r.client.Scan(0, path+"/*", defaultCount).Result()
	if err != nil {
		return nil, err
	}
	if len(keys) > 0 {
		return &redisFileInfo{
			name:  path,
			size:  0,
			isDir: true,
		}, nil
	}
	// Otherwise, there is no such file.
	return nil, os.ErrNotExist
}

func (r *redisStorage) Exists(path string) (bool, error) {
	count, err := r.client.Exists(path).Result()
	if err != nil {
		return false, err
	}
	return (count > 0), nil
}

func (r *redisStorage) ReadDir(path string) ([]os.FileInfo, error) {
	keys := make([]string, 0)
	var cursor uint64
	for {
		nextKeys, nextCursor, err := r.client.Scan(cursor, path+"/*", defaultCount).Result()
		if err != nil {
			return nil, err
		}
		cursor = nextCursor
		keys = append(keys, nextKeys...)
		if cursor == 0 {
			break
		}
	}
	// We do not distinguish between empty directories and missing directories.
	// However, keystore never creates empty directories so assume it's missing.
	if len(keys) == 0 {
		return nil, os.ErrNotExist
	}
	// Scan will traverse all 'subdirectories' too, but we want only direct children.
	// Currently we should not have nested directories but handle them just in case.
	// TODO: examples, why this code piece looks like this
	prefix := path + "/"
	fileInfos := make([]os.FileInfo, 0, len(keys))
	seenDirectories := make(map[string]struct{})
	for _, key := range keys {
		name := strings.TrimPrefix(key, prefix)
		idx := strings.Index(name, "/")
		if idx == -1 {
			fileInfos = append(fileInfos, &redisFileInfo{
				name:  name,
				size:  0, // TODO: would be nice to retrieve, but we don't need it
				isDir: false,
			})
		} else {
			dirName := name[0:idx]
			_, seen := seenDirectories[dirName]
			if !seen {
				fileInfos = append(fileInfos, &redisFileInfo{
					name:  dirName,
					size:  0,
					isDir: true,
				})
				seenDirectories[dirName] = struct{}{}
			}
		}
	}
	return fileInfos, nil
}

func (r *redisStorage) MkdirAll(path string, perm os.FileMode) error {
	// We don't maintain hierarchy in Redis directly, it's all in key names
	return nil
}

func (r *redisStorage) Rename(oldpath, newpath string) error {
	_, err := r.client.Rename(oldpath, newpath).Result()
	return err
}

const maxTempFileAttempts = 10

var errNoLuck = errors.New("failed to create temporary file")

func (r *redisStorage) TempFile(pattern string, perm os.FileMode) (string, error) {
	for i := 0; i < maxTempFileAttempts; i++ {
		path := pattern + fmt.Sprintf("%06d", rand.Int())
		err := r.client.SetNX(path, "", noExpiration).Err()
		if err == nil {
			return path, nil
		}
	}
	return "", errNoLuck
}

func (r *redisStorage) TempDir(pattern string, perm os.FileMode) (string, error) {
	// Redis does not track directories, so the returned path is not guaranteed
	//to remain free, but this method is only used for tests so it's fine.
	for i := 0; i < maxTempFileAttempts; i++ {
		path := pattern + fmt.Sprintf(".%06d", rand.Int())
		n, err := r.client.Exists(path).Result()
		if err != nil || n > 0 {
			continue
		}
		keys, _, err := r.client.Scan(0, path+"/*", defaultCount).Result()
		if err != nil || len(keys) > 0 {
			continue
		}
		return path, nil
	}
	return "", errNoLuck
}

var errNotSupported = errors.New("operation not supported")

func (r *redisStorage) Link(oldpath, newpath string) error {
	// Redis does not support hard links for keys. Please copy.
	return errNotSupported
}

const noExpiration = 0

func (r *redisStorage) Copy(src, dst string) error {
	data, err := r.client.Get(src).Result()
	if err != nil {
		return fixupENOENT(err)
	}
	err = r.client.SetNX(dst, data, noExpiration).Err()
	if err != nil {
		return fixupEEXIST(err)
	}
	return nil
}

func (r *redisStorage) ReadFile(path string) ([]byte, error) {
	b64, err := r.client.Get(path).Result()
	if err != nil {
		return nil, fixupENOENT(err)
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (r *redisStorage) WriteFile(path string, data []byte, perm os.FileMode) error {
	b64 := base64.StdEncoding.EncodeToString(data)
	err := r.client.Set(path, b64, noExpiration).Err()
	if err != nil {
		return err
	}
	return nil
}

func (r *redisStorage) Remove(path string) error {
	n, err := r.client.Del(path).Result()
	if err != nil {
		return err
	}
	// Remove expects the removed path to exist
	if n != 1 {
		return os.ErrNotExist
	}
	return nil
}

func (r *redisStorage) RemoveAll(path string) error {
	keys := make([]string, 1)
	keys[0] = path
	// There might be no child elements at all, or there might be no key named "path".
	// RemoveAll does not produce an error in these cases. In only ensures that neither
	// "${path}" nor any "${path}/*" refers to anything anymore.
	var cursor uint64
	for {
		nextKeys, nextCursor, err := r.client.Scan(cursor, path+"/*", defaultCount).Result()
		if err != nil {
			return err
		}
		cursor = nextCursor
		keys = append(keys, nextKeys...)
		if cursor == 0 {
			break
		}
	}
	_, err := r.client.Del(keys...).Result()
	if err != nil {
		return err
	}
	return nil
}
