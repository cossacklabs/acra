package kms

import (
	"context"
	"errors"
	"strings"
	"sync"
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
}

// GetEncryptorCreator return EncryptorCreator by its ID from registry
func GetEncryptorCreator(encryptorID string) (EncryptorCreateFunc, bool) {
	creator, ok := encryptorCreators[encryptorID]
	return creator, ok
}

// KeyID validation related errors
var (
	ErrInvalidKeyIDFormat     = errors.New("invalid keyID URI format")
	ErrUnsupportedKeyIDFormat = errors.New("unsupported keyID URI format")
)

//go:generate mockery --name Encryptor --output ../mocks --filename KmsEncryptor.go

// Encryptor is main kms encryptor interface
type Encryptor interface {
	ID() string
	Encrypt(ctx context.Context, keyID string, data []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyID string, data []byte) ([]byte, error)
}

// KeyIdentifier represent KMS KeyID in Tink format
// https://developers.google.com/tink/get-key-uri
type KeyIdentifier struct {
	id, prefix string
}

// NewKeyIdentifierFromURI create new KeyIdentifier from provided value
// expected value: `aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>`
func NewKeyIdentifierFromURI(value string) (KeyIdentifier, error) {
	splits := strings.Split(value, "//")
	if len(splits) != 2 {
		return KeyIdentifier{}, ErrInvalidKeyIDFormat
	}
	prefix := splits[0]
	_, ok := GetEncryptorCreator(splits[0])
	if !ok {
		return KeyIdentifier{}, ErrUnsupportedKeyIDFormat
	}

	return KeyIdentifier{
		prefix: prefix,
		id:     splits[1],
	}, nil
}

// ID return keyID without prefix
func (k KeyIdentifier) ID() string {
	return k.id
}

// Prefix return keyID prefix
func (k KeyIdentifier) Prefix() string {
	return k.prefix
}
