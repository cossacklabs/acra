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
