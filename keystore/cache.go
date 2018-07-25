package keystore

const (
	// INFINITE_CACHE_SIZE unlimited size
	INFINITE_CACHE_SIZE = 0
	// NO_CACHE
	NO_CACHE = -1
)

// NoCache is cache implementation for case when keystore should not to use any cache
type NoCache struct{}

// Add
func (NoCache) Add(keyId string, keyValue []byte) {
}

// Get
func (NoCache) Get(keyId string) ([]byte, bool) {
	return nil, false
}

// Clear
func (NoCache) Clear() {
}

// Cache that used by FilesystemKeystore to cache loaded keys from filesystem
type Cache interface {
	Add(keyId string, keyValue []byte)
	Get(keyId string) ([]byte, bool)
	Clear()
}
