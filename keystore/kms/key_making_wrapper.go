package kms

import (
	"context"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
)

// KeyMakingWrapper wrap keystore.KeyMaking implementation with KMS key creation at start
type KeyMakingWrapper struct {
	keystore.KeyMaking
	kmsKeyManager KeyManager
}

// NewKeyMakingWrapper create new KeyMakingWrapper
func NewKeyMakingWrapper(keyMaking keystore.KeyMaking, manager KeyManager) KeyMakingWrapper {
	return KeyMakingWrapper{
		KeyMaking:     keyMaking,
		kmsKeyManager: manager,
	}
}

// GenerateDataEncryptionKeys wrap GenerateDataEncryptionKeys with KMS key creation at start
func (k KeyMakingWrapper) GenerateDataEncryptionKeys(clientID []byte) error {
	err := k.createKMSKeyFromContext(keystore.KeyContext{
		ClientID: clientID,
		Purpose:  keystore.PurposeStorageClientPrivateKey,
	})
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateDataEncryptionKeys(clientID)
}

// GeneratePoisonSymmetricKey wrap GeneratePoisonSymmetricKey with KMS key creation at start
func (k KeyMakingWrapper) GeneratePoisonSymmetricKey() error {
	err := k.createKMSKeyFromContext(keystore.KeyContext{
		Purpose: keystore.PurposePoisonRecordSymmetricKey,
	})
	if err != nil {
		return err
	}

	return k.KeyMaking.GeneratePoisonSymmetricKey()
}

// GeneratePoisonKeyPair wrap GeneratePoisonKeyPair with KMS key creation at start
func (k KeyMakingWrapper) GeneratePoisonKeyPair() error {
	err := k.createKMSKeyFromContext(keystore.KeyContext{
		Purpose: keystore.PurposePoisonRecordKeyPair,
	})
	if err != nil {
		return err
	}

	return k.KeyMaking.GeneratePoisonKeyPair()
}

// GenerateLogKey wrap GenerateLogKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateLogKey() error {
	err := k.createKMSKeyFromContext(keystore.KeyContext{
		Purpose: keystore.PurposeAuditLog,
	})
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateLogKey()
}

// GenerateHmacKey wrap GenerateHmacKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateHmacKey(clientID []byte) error {
	err := k.createKMSKeyFromContext(keystore.KeyContext{
		ClientID: clientID,
		Purpose:  keystore.PurposeSearchHMAC,
	})
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateHmacKey(clientID)
}

// GenerateClientIDSymmetricKey wrap GenerateClientIDSymmetricKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateClientIDSymmetricKey(id []byte) error {
	err := k.createKMSKeyFromContext(keystore.KeyContext{
		ClientID: id,
		Purpose:  keystore.PurposeStorageClientSymmetricKey,
	})
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateClientIDSymmetricKey(id)
}

func (k KeyMakingWrapper) createKMSKeyFromContext(keyContext keystore.KeyContext) error {
	ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)

	keyID, err := getKeyIDFromContext(keyContext)
	if err != nil {
		return err
	}

	resp, err := k.kmsKeyManager.CreateKey(ctx, CreateKeyMetadata{
		KeyName: string(keyID),
	})
	if err != nil {
		return err
	}
	log.WithField("purpose", keyContext.Purpose).WithField("keyID", resp.KeyID).Info("KMS key created")
	return nil
}
