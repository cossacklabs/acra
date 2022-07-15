package kms

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
)

var lock = sync.Mutex{}
var keystoreCreators = map[string]KeystoreCreateFunc{}

// KeystoreCreateFunc generic function for creating Encryptor
type KeystoreCreateFunc func(credentialPath string) (Keystore, error)

// RegisterKeystoreCreator add new EncryptorCreator to registry
func RegisterKeystoreCreator(encryptorID string, keystoreCreateFunc KeystoreCreateFunc) {
	lock.Lock()
	keystoreCreators[encryptorID] = keystoreCreateFunc
	lock.Unlock()
	log.WithField("encryptor", encryptorID).Debug("Registered KMS keystore creator")
}

// GetKeystoreCreator return KeystoreCreator by its ID from registry
func GetKeystoreCreator(encryptorID string) (KeystoreCreateFunc, bool) {
	creator, ok := keystoreCreators[encryptorID]
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

//go:generate mockery --name Keystore --output ../mocks --filename KmsKeystore.go
// Keystore is main kms keystore interface
type Keystore interface {
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
