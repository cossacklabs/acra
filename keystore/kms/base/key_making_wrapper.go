package base

import (
	"context"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
)

// KMS kek descriptions
const (
	AcraClientKeyDescription   = "Acra client key encryption key, used for encryption/decryption AcraBlock symmetric key, AcraStruct private key and HMAC symmetric key"
	AcraPoisonKeyDescription   = "Acra common key encryption key, used for encryption/decryption poison symmetric/private keys"
	AcraAuditLogKeyDescription = "Acra common key encryption key, used for encryption/decryption audit log key"
)

// KeyMaking interface used by KMS wrapper for generating keys
type KeyMaking interface {
	keystore.KeyMaking
	keystore.PoisonKeyStorageAndGenerator
}

// KeyMakingWrapper wrap keystore.KeyMaking implementation with KMS key creation at start
type KeyMakingWrapper struct {
	KeyMaking
	kmsKeyManager KeyManager
	keyMapper     KeyMapper
}

// NewKeyMakingWrapper create new KeyMakingWrapper
func NewKeyMakingWrapper(keyMaking KeyMaking, manager KeyManager, keyMapper KeyMapper) KeyMakingWrapper {
	return KeyMakingWrapper{
		KeyMaking:     keyMaking,
		kmsKeyManager: manager,
		keyMapper:     keyMapper,
	}
}

// GenerateDataEncryptionKeys wrap GenerateDataEncryptionKeys with KMS key creation at start
func (k KeyMakingWrapper) GenerateDataEncryptionKeys(clientID []byte) error {
	ctx := keystore.KeyContext{
		ClientID: clientID,
		Purpose:  keystore.PurposeStorageClientPrivateKey,
	}

	err := k.createKMSKeyFromContext(ctx, AcraClientKeyDescription)
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateDataEncryptionKeys(clientID)
}

// GeneratePoisonSymmetricKey wrap GeneratePoisonSymmetricKey with KMS key creation at start
func (k KeyMakingWrapper) GeneratePoisonSymmetricKey() error {
	ctx := keystore.KeyContext{
		Purpose: keystore.PurposePoisonRecordSymmetricKey,
	}

	err := k.createKMSKeyFromContext(ctx, AcraPoisonKeyDescription)
	if err != nil {
		return err
	}

	return k.KeyMaking.GeneratePoisonSymmetricKey()
}

// GeneratePoisonKeyPair wrap GeneratePoisonKeyPair with KMS key creation at start
func (k KeyMakingWrapper) GeneratePoisonKeyPair() error {
	ctx := keystore.KeyContext{
		Purpose: keystore.PurposePoisonRecordKeyPair,
	}

	err := k.createKMSKeyFromContext(ctx, AcraPoisonKeyDescription)
	if err != nil {
		return err
	}

	return k.KeyMaking.GeneratePoisonKeyPair()
}

// GenerateLogKey wrap GenerateLogKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateLogKey() error {
	ctx := keystore.KeyContext{
		Purpose: keystore.PurposeAuditLog,
	}

	err := k.createKMSKeyFromContext(ctx, AcraAuditLogKeyDescription)
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateLogKey()
}

// GenerateHmacKey wrap GenerateHmacKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateHmacKey(clientID []byte) error {
	ctx := keystore.KeyContext{
		ClientID: clientID,
		Purpose:  keystore.PurposeSearchHMAC,
	}

	err := k.createKMSKeyFromContext(ctx, AcraClientKeyDescription)
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateHmacKey(clientID)
}

// GenerateClientIDSymmetricKey wrap GenerateClientIDSymmetricKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateClientIDSymmetricKey(id []byte) error {
	ctx := keystore.KeyContext{
		ClientID: id,
		Purpose:  keystore.PurposeStorageClientSymmetricKey,
	}

	err := k.createKMSKeyFromContext(ctx, AcraClientKeyDescription)
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateClientIDSymmetricKey(id)
}

func (k KeyMakingWrapper) createKMSKeyFromContext(keyContext keystore.KeyContext, description string) error {
	ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)

	keyID, err := k.keyMapper.GetKeyID(keyContext)
	if err != nil {
		return err
	}

	keyExist, err := k.kmsKeyManager.IsKeyExist(ctx, string(keyID))
	if err != nil {
		return err
	}

	if keyExist {
		log.WithField("keyID", string(keyID)).Debugln("KMS key already exist")
		return nil
	}

	resp, err := k.kmsKeyManager.CreateKey(ctx, CreateKeyMetadata{
		KeyName:     string(keyID),
		Description: description,
	})
	if err != nil {
		return err
	}

	log.WithField("keyID", resp.KeyID).WithField("key-name", string(keyID)).Info("KMS key created")
	return nil
}
