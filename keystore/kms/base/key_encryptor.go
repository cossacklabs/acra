package base

import (
	"context"

	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// KeyEncryptor implementation of KMS keystore.KeyEncryptor
type KeyEncryptor struct {
	kmsEncryptor Encryptor
	keyMapper    KeyMapper
}

// NewKeyEncryptor create new KeyEncryptor
func NewKeyEncryptor(kmsEncryptor Encryptor, keyMapper KeyMapper) *KeyEncryptor {
	return &KeyEncryptor{
		kmsEncryptor: kmsEncryptor,
		keyMapper:    keyMapper,
	}
}

// Encrypt return encrypted key using KMS encryptor and context.
func (encryptor *KeyEncryptor) Encrypt(ctx context.Context, key []byte, keyContext keystore.KeyContext) ([]byte, error) {
	keyID, err := encryptor.keyMapper.GetKeyID(keyContext)
	if err != nil {
		log.WithError(err).Errorln("Failed to obtain keyID from keyContext")
		return nil, err
	}
	return encryptor.kmsEncryptor.Encrypt(ctx, keyID, key, nil)
}

// Decrypt return decrypted key using KMS encryptor and context.
func (encryptor *KeyEncryptor) Decrypt(ctx context.Context, key []byte, keyContext keystore.KeyContext) ([]byte, error) {
	keyID, err := encryptor.keyMapper.GetKeyID(keyContext)
	if err != nil {
		log.WithError(err).Errorln("Failed to obtain keyID from keyContext")
		return nil, err
	}
	return encryptor.kmsEncryptor.Decrypt(ctx, keyID, key, nil)
}
