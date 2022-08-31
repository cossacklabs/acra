package base

import (
	"context"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"time"
)

// KMS kek descriptions
const (
	AcraClientKeyDescription   = "Acra client key encryption key, used for encryption/decryption AcraBlock symmetric key, AcraStruct private key and HMAC symmetric key"
	AcraZoneKeyDescription     = "Acra zone key encryption key, used for encryption/decryption Zone symmetric key and Zone private key"
	AcraPoisonKeyDescription   = "Acra common key encryption key, used for encryption/decryption poison symmetric/private keys"
	AcraAuditLogKeyDescription = "Acra common key encryption key, used for encryption/decryption audit log key"
)

// KeyMaking interface used by KMS wrapper for generating keys
type KeyMaking interface {
	zone.KeyChecker
	keystore.KeyMaking
	keystore.PoisonKeyStorageAndGenerator
}

// KeyMakingWrapper wrap keystore.KeyMaking implementation with KMS key creation at start
type KeyMakingWrapper struct {
	KeyMaking
	kmsKeyManager KeyManager
}

// NewKeyMakingWrapper create new KeyMakingWrapper
func NewKeyMakingWrapper(keyMaking KeyMaking, manager KeyManager) KeyMakingWrapper {
	return KeyMakingWrapper{
		KeyMaking:     keyMaking,
		kmsKeyManager: manager,
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

// GenerateZoneKey wrap GenerateZoneKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateZoneKey() ([]byte, []byte, error) {
	var id []byte
	for {
		// generate until key not exists
		id = zone.GenerateZoneID()
		if !k.KeyMaking.HasZonePrivateKey(id) {
			break
		}
	}

	ctx := keystore.KeyContext{
		ZoneID:  id,
		Purpose: keystore.PurposeStorageZoneKeyPair,
	}

	err := k.createKMSKeyFromContext(ctx, AcraZoneKeyDescription)
	if err != nil {
		return nil, nil, err
	}

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		return nil, nil, err
	}
	return id, keypair.Public.Value, k.KeyMaking.SaveZoneKeypair(id, keypair)
}

// GenerateZoneIDSymmetricKey wrap GenerateZoneIDSymmetricKey with KMS key creation at start
func (k KeyMakingWrapper) GenerateZoneIDSymmetricKey(id []byte) error {
	ctx := keystore.KeyContext{
		ZoneID:  id,
		Purpose: keystore.PurposeStorageZoneSymmetricKey,
	}

	err := k.createKMSKeyFromContext(ctx, AcraZoneKeyDescription)
	if err != nil {
		return err
	}

	return k.KeyMaking.GenerateZoneIDSymmetricKey(id)
}

func (k KeyMakingWrapper) createKMSKeyFromContext(keyContext keystore.KeyContext, description string) error {
	ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)

	keyID, err := getKeyIDFromContext(keyContext)
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

	// wait some time for alias to be active
	for {
		keyExist, err = k.kmsKeyManager.IsKeyExist(ctx, string(keyID))
		if err != nil {
			return err
		}

		if keyExist {
			return nil
		}
		time.Sleep(time.Millisecond * 100)
	}
}
