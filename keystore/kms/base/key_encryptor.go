package base

import (
	"context"
	"errors"
	"github.com/cossacklabs/acra/keystore"
	log "github.com/sirupsen/logrus"
)

// KmsEncryptor errors
var (
	ErrMissingKeyPurpose     = errors.New("key purpose is required for keyID creating")
	ErrUnsupportedKeyPurpose = errors.New("unsupported KeyPurpose option provided")
	ErrEmptyClientIDProvided = errors.New("empty clientID in key context")
	ErrEmptyZoneIDProvided   = errors.New("empty zoneID in key context")
)

// KeyEncryptor implementation of KMS keystore.KeyEncryptor
type KeyEncryptor struct {
	kmsEncryptor Encryptor
}

// NewKeyEncryptor create new KeyEncryptor
func NewKeyEncryptor(kmsEncryptor Encryptor) *KeyEncryptor {
	return &KeyEncryptor{
		kmsEncryptor,
	}
}

// Encrypt return encrypted key using KMS encryptor and context.
func (encryptor *KeyEncryptor) Encrypt(ctx context.Context, key []byte, keyContext keystore.KeyContext) ([]byte, error) {
	keyID, err := getKeyIDFromContext(keyContext)
	if err != nil {
		log.WithError(err).Errorln("Failed to obtain keyID from keyContext")
		return nil, err
	}
	return encryptor.kmsEncryptor.Encrypt(ctx, keyID, key, nil)
}

// Decrypt return decrypted key using KMS encryptor and context.
func (encryptor *KeyEncryptor) Decrypt(ctx context.Context, key []byte, keyContext keystore.KeyContext) ([]byte, error) {
	keyID, err := getKeyIDFromContext(keyContext)
	if err != nil {
		log.WithError(err).Errorln("Failed to obtain keyID from keyContext")
		return nil, err
	}
	return encryptor.kmsEncryptor.Decrypt(ctx, keyID, key, nil)
}

func getKeyIDFromContext(ctx keystore.KeyContext) ([]byte, error) {
	if ctx.Purpose == "" {
		return nil, ErrMissingKeyPurpose
	}

	switch ctx.Purpose {
	case keystore.PurposeStorageClientSymmetricKey, keystore.PurposeStorageClientPrivateKey, keystore.PurposeSearchHMAC:
		if ctx.ClientID == nil {
			return nil, ErrEmptyClientIDProvided
		}
		return []byte("acra_" + string(ctx.ClientID)), nil
	case keystore.PurposeStorageZoneSymmetricKey, keystore.PurposeStorageZonePrivateKey, keystore.PurposeStorageZoneKeyPair:
		if ctx.ZoneID == nil {
			return nil, ErrEmptyZoneIDProvided
		}
		return []byte("acra_" + string(ctx.ZoneID)), nil
	case keystore.PurposePoisonRecordSymmetricKey, keystore.PurposePoisonRecordKeyPair:
		return []byte("acra_poison"), nil
	case keystore.PurposeAuditLog:
		return []byte("acra_audit_log"), nil
	default:
		return nil, ErrUnsupportedKeyPurpose
	}
}
