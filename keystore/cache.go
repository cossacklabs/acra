package keystore

const (
	INFINITE_CACHE_SIZE = 0
	NO_CACHE            = -1
)

type NoCache struct{}

func (NoCache) Add(keyId string, keyValue []byte) {
}

func (NoCache) Get(keyId string) ([]byte, bool) {
	return nil, false
}

func (NoCache) Clear() {
}

type Cache interface {
	Add(keyId string, keyValue []byte)
	Get(keyId string) ([]byte, bool)
	Clear()
}
