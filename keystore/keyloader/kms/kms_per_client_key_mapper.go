package kms

import (
	"errors"

	"github.com/cossacklabs/acra/keystore"
)

// KmsEncryptor errors
var (
	ErrMissingKeyPurpose     = errors.New("key purpose is required for keyID creating")
	ErrUnsupportedKeyPurpose = errors.New("unsupported KeyPurpose option provided")
	ErrEmptyClientIDProvided = errors.New("empty clientID in key context")
	ErrEmptyZoneIDProvided   = errors.New("empty zoneID in key context")
)

// KeyMapper Implement KeyMapper interface for `kms_per_client` strategy
type KeyMapper struct{}

// NewKMSPerClientKeyMapper create new KeyMapper
func NewKMSPerClientKeyMapper() *KeyMapper {
	return &KeyMapper{}
}

// GetKeyID implementation method of KeyMapper interface
func (k *KeyMapper) GetKeyID(ctx keystore.KeyContext) ([]byte, error) {
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
