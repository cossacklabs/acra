package kms

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
)

var lock = sync.Mutex{}
var keyManagerCreators = map[string]KeyManagerCreateFunc{}

// KeyManagerCreateFunc generic function for creating KeyManager
type KeyManagerCreateFunc func(credentialPath string) (KeyManager, error)

// RegisterKeyManagerCreator add new kms KeyManager to registry
func RegisterKeyManagerCreator(encryptorID string, keyMangerCreateFunc KeyManagerCreateFunc) {
	lock.Lock()
	keyManagerCreators[encryptorID] = keyMangerCreateFunc
	lock.Unlock()
	log.WithField("encryptor", encryptorID).Debug("Registered KMS KeyManager creator")
}

// GetKeyManagerCreator return KeyManagerCreateFunc by its ID from registry
func GetKeyManagerCreator(encryptorID string) (KeyManagerCreateFunc, bool) {
	creator, ok := keyManagerCreators[encryptorID]
	return creator, ok
}

// CreateKeyMetadata represent common structure for creating KMS key
type CreateKeyMetadata struct {
	KeyName     string
	Description string
}

// KeyMetadata represent structure that store key creation result
type KeyMetadata struct {
	KeyID string
}

//go:generate mockery --name KeyManager --output ../mocks --filename KeyManager.go
// KeyManager is main kms interface
type KeyManager interface {
	Encryptor

	ID() string
	CreateKey(ctx context.Context, metaData CreateKeyMetadata) (*KeyMetadata, error)
	IsKeyExist(ctx context.Context, keyID string) (bool, error)
}

//go:generate mockery --name Encryptor --output ../mocks --filename KmsEncryptor.go

// Encryptor is main kms encryptor interface
type Encryptor interface {
	Encrypt(ctx context.Context, keyID []byte, data []byte, context []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyID []byte, data []byte, context []byte) ([]byte, error)
}
