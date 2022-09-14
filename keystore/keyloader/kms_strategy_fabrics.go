package keyloader

import (
	"flag"

	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	baseKMS "github.com/cossacklabs/acra/keystore/kms/base"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	log "github.com/sirupsen/logrus"
)

// KmsMasterKeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `kms_encrypted_master_key` strategy
type KmsMasterKeyEncryptorFabric struct{}

// KmsPerClientKeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `kms_per_client` strategy
type KmsPerClientKeyEncryptorFabric struct{}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `kms_encrypted_master_key` strategy
func (k KmsMasterKeyEncryptorFabric) NewKeyEncryptor(flags *flag.FlagSet, prefix string) (keystore.KeyEncryptor, error) {
	kmsOptions := kms.ParseCLIParametersFromFlags(flags, prefix)

	keyManager, err := kms.NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	loader := kms.NewLoader(keyManager)

	key, err := loader.LoadMasterKey()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	return keystore.NewSCellKeyEncryptor(key)
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `kms_encrypted_master_key` strategy
func (k KmsMasterKeyEncryptorFabric) NewKeyEncryptorSuite(flags *flag.FlagSet, prefix string) (*crypto.KeyStoreSuite, error) {
	kmsOptions := kms.ParseCLIParametersFromFlags(flags, prefix)

	keyManager, err := kms.NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	loader := kms.NewLoader(keyManager)

	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master keys")
		return nil, err
	}
	return keystoreV2.NewSCellSuite(encryption, signature)
}

// RegisterCLIParameters empty implementation of KMSMasterKeyKeyEncryptorFabric interface
func (k KmsMasterKeyEncryptorFabric) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	kms.RegisterCLIParametersWithFlags(flags, prefix, description)
}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `kms_per_client` strategy
func (k KmsPerClientKeyEncryptorFabric) NewKeyEncryptor(flags *flag.FlagSet, prefix string) (keystore.KeyEncryptor, error) {
	kmsOptions := kms.ParseCLIParametersFromFlags(flags, prefix)

	keyManager, err := kms.NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	keyMapper, err := NewKeyMapper(kmsOptions.KMSType, KeystoreStrategyKMSPerClient)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	return baseKMS.NewKeyEncryptor(keyManager, keyMapper), nil
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `kms_per_client` strategy
func (k KmsPerClientKeyEncryptorFabric) NewKeyEncryptorSuite(flags *flag.FlagSet, prefix string) (*crypto.KeyStoreSuite, error) {
	kmsOptions := kms.ParseCLIParametersFromFlags(flags, prefix)

	keyManager, err := kms.NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	keyMapper, err := NewKeyMapper(kmsOptions.KMSType, KeystoreStrategyKMSPerClient)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	loader := kms.NewLoader(keyManager)

	// TODO think about multiplexing kms_per_client strategy and keyloader strategy
	_, signature, err := loader.LoadMasterKeys()
	if err != nil {
		return nil, err
	}

	return crypto.NewSCellSuiteWithEncryptor(baseKMS.NewKeyEncryptor(keyManager, keyMapper), signature)
}

// RegisterCLIParameters empty implementation of KMSMasterKeyKeyEncryptorFabric interface
func (k KmsPerClientKeyEncryptorFabric) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	kms.RegisterCLIParametersWithFlags(flags, prefix, description)
}
