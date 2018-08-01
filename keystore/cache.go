/*
Copyright 2016, Cossack Labs Limited

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

package keystore

const (
	// INFINITE_CACHE_SIZE unlimited size
	INFINITE_CACHE_SIZE = 0
	// NO_CACHE means not using cache at all
	NO_CACHE = -1
)

// NoCache is cache implementation for case when keystore should not to use any cache
type NoCache struct{}

// Add empty implementation
func (NoCache) Add(keyID string, keyValue []byte) {
}

// Get empty implementation
func (NoCache) Get(keyID string) ([]byte, bool) {
	return nil, false
}

// Clear empty implementation
func (NoCache) Clear() {
}

// Cache that used by FilesystemKeystore to cache loaded keys from filesystem
type Cache interface {
	Add(keyID string, keyValue []byte)
	Get(keyID string) ([]byte, bool)
	Clear()
}
