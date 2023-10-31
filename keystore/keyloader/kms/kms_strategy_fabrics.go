package kms

import (
	"flag"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	baseKMS "github.com/cossacklabs/acra/keystore/kms/base"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
)

// MasterKeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `kms_encrypted_master_key` strategy
type MasterKeyEncryptorFabric struct{}

// PerClientKeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `kms_per_client` strategy
type PerClientKeyEncryptorFabric struct{}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `kms_encrypted_master_key` strategy
func (k MasterKeyEncryptorFabric) NewKeyEncryptor(extractor *cmd.ServiceParamsExtractor, prefix string) (keystore.KeyEncryptor, error) {
	kmsOptions := ParseCLIParametersFromFlags(extractor, prefix)

	keyManager, err := NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	loader := NewLoader(keyManager)

	key, err := loader.LoadMasterKey()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		return nil, err
	}
	return keystore.NewSCellKeyEncryptor(key)
}

// GetKeyMapper return KeyMapper for `kms_encrypted_master_key` strategy
func (k MasterKeyEncryptorFabric) GetKeyMapper() baseKMS.KeyMapper {
	panic("No KeyMapper for kms_encrypted_master_key strategy")
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `kms_encrypted_master_key` strategy
func (k MasterKeyEncryptorFabric) NewKeyEncryptorSuite(extractor *cmd.ServiceParamsExtractor, prefix string) (*crypto.KeyStoreSuite, error) {
	kmsOptions := ParseCLIParametersFromFlags(extractor, prefix)

	keyManager, err := NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	loader := NewLoader(keyManager)

	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master keys")
		return nil, err
	}
	return keystoreV2.NewSCellSuite(encryption, signature)
}

// RegisterCLIParameters empty implementation of KMSMasterKeyKeyEncryptorFabric interface
func (k MasterKeyEncryptorFabric) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	RegisterCLIParametersWithFlags(flags, prefix, description)
}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `kms_per_client` strategy
func (k PerClientKeyEncryptorFabric) NewKeyEncryptor(extractor *cmd.ServiceParamsExtractor, prefix string) (keystore.KeyEncryptor, error) {
	kmsOptions := ParseCLIParametersFromFlags(extractor, prefix)

	keyManager, err := NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}

	return baseKMS.NewKeyEncryptor(keyManager, k.GetKeyMapper()), nil
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `kms_per_client` strategy
func (k PerClientKeyEncryptorFabric) NewKeyEncryptorSuite(extractor *cmd.ServiceParamsExtractor, prefix string) (*crypto.KeyStoreSuite, error) {
	kmsOptions := ParseCLIParametersFromFlags(extractor, prefix)

	keyManager, err := NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}
	loader := NewLoader(keyManager)

	// TODO think about multiplexing kms_per_client strategy and keyloader strategy
	_, signature, err := loader.LoadMasterKeys()
	if err != nil {
		return nil, err
	}

	return crypto.NewSCellSuiteWithEncryptor(baseKMS.NewKeyEncryptor(keyManager, k.GetKeyMapper()), signature)
}

// RegisterCLIParameters empty implementation of KMSMasterKeyKeyEncryptorFabric interface
func (k PerClientKeyEncryptorFabric) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	RegisterCLIParametersWithFlags(flags, prefix, description)
}

// GetKeyMapper return KeyMapper for `kms_per_client` strategy
func (k PerClientKeyEncryptorFabric) GetKeyMapper() baseKMS.KeyMapper {
	return NewKMSPerClientKeyMapper()
}
