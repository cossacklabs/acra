package kms

import (
	"context"
	"crypto/subtle"
	"github.com/cossacklabs/acra/keystore"
	keystoreCE "github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/kms"
	keystoreV2CE "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/network"
	log "github.com/sirupsen/logrus"
)

// Loader is implementation of MasterKeyLoader for kms
type Loader struct {
	encryptor kms.Encryptor
}

// NewLoader create new kms MasterKeyLoader
func NewLoader(encryptor kms.Encryptor) *Loader {
	return &Loader{
		encryptor: encryptor,
	}
}

// LoadMasterKey implementation kms MasterKeyLoader for loading AcraMasterKey for keystore v1
func (loader *Loader) LoadMasterKey() ([]byte, error) {
	rawKey, err := loader.decryptWithKMSKey([]byte(AcraMasterKeyKEKID))
	if err != nil {
		log.WithError(err).Warnf("Failed to decrypt ACRA_MASTER_KEY with KMS keyID %s", AcraMasterKeyKEKID)
		return nil, err
	}

	if err := keystoreCE.ValidateMasterKey(rawKey); err != nil {
		log.WithError(err).Warn("Decrypted key is invalid")
		return nil, err
	}

	return rawKey, nil
}

// LoadMasterKeys implementation kms MasterKeyLoader for loading AcraMasterKey for keystore v2
func (loader *Loader) LoadMasterKeys() (encryption []byte, signature []byte, err error) {
	rawKey, err := loader.decryptWithKMSKey([]byte(AcraMasterKeyKEKID))
	if err != nil {
		log.WithError(err).Warnf("Failed to decrypt ACRA_MASTER_KEY with KMS keyID %s", AcraMasterKeyKEKID)
		return nil, nil, err
	}

	keys := &keystoreV2CE.SerializedKeys{}
	err = keys.Unmarshal(rawKey)
	if err != nil {
		log.WithError(err).Warn("Failed to parse KMS decrypted key as SerializedKeys")
		return nil, nil, err
	}

	if subtle.ConstantTimeCompare(keys.Encryption, keys.Signature) == 1 {
		log.Warn("ACRA_MASTER_KEYs must not be the same")
		return nil, nil, keystoreV2CE.ErrEqualMasterKeys
	}

	err = keystoreCE.ValidateMasterKey(keys.Encryption)
	if err != nil {
		log.WithError(err).Warn("Invalid encryption key")
		return nil, nil, err
	}
	err = keystoreCE.ValidateMasterKey(keys.Signature)
	if err != nil {
		log.WithError(err).Warn("Invalid signature key")
		return nil, nil, err
	}

	return keys.Encryption, keys.Signature, nil
}

func (loader *Loader) decryptWithKMSKey(keyID []byte) ([]byte, error) {
	cipherMasterKey, err := keystore.GetMasterKeyFromEnvironmentVariable(keystore.AcraMasterKeyVarName)
	if err != nil {
		return nil, err
	}

	ctx, _ := context.WithTimeout(context.Background(), network.DefaultNetworkTimeout)
	masterKey, err := loader.encryptor.Decrypt(ctx, keyID, cipherMasterKey, nil)
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}
