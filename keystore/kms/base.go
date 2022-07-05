package kms

import (
	"errors"
	"strings"

	"github.com/cossacklabs/acra/keystore/kms/aws"
)

// KeyID validation related errors
var (
	ErrInvalidKeyIDFormat     = errors.New("invalid keyID URI format")
	ErrUnsupportedKeyIDFormat = errors.New("unsupported keyID URI format")
)

var supportedKeyURIs = map[string]struct{}{
	aws.KeyIdentifierPrefix: {},
}

// Encryptor is main kms encryptor interface
type Encryptor interface {
	Source() string
	Encrypt(keyID string, data []byte) ([]byte, error)
	Decrypt(keyID string, data []byte) ([]byte, error)
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
	_, ok := supportedKeyURIs[splits[0]]
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
