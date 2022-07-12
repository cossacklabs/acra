package kms

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
)

var lock = sync.Mutex{}
var encryptorCreators = map[string]EncryptorCreateFunc{}

// EncryptorCreateFunc generic function for creating Encryptor
type EncryptorCreateFunc func(credentialPath string) (Encryptor, error)

// RegisterEncryptorCreator add new EncryptorCreator to registry
func RegisterEncryptorCreator(encryptorID string, encryptorCreateFunc EncryptorCreateFunc) {
	lock.Lock()
	encryptorCreators[encryptorID] = encryptorCreateFunc
	lock.Unlock()
	log.WithField("encryptor", encryptorID).Debug("Registered KMS Encryptor creator")
}

// GetEncryptorCreator return EncryptorCreator by its ID from registry
func GetEncryptorCreator(encryptorID string) (EncryptorCreateFunc, bool) {
	creator, ok := encryptorCreators[encryptorID]
	return creator, ok
}

//go:generate mockery --name Encryptor --output ../mocks --filename KmsEncryptor.go

// Encryptor is main kms encryptor interface
type Encryptor interface {
	ID() string
	Encrypt(ctx context.Context, keyID string, data []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyID string, data []byte) ([]byte, error)
}

// AcraMasterKeyKEKID represent ID/alias of encryption key used for MasterKey loading
const AcraMasterKeyKEKID = "acra_master_key"

// TypeAWS supported KMS type AWS
const TypeAWS = "aws"

// SupportedTypes contains all possible values for flag `--kms_type`
var SupportedTypes = []string{
	TypeAWS,
}
