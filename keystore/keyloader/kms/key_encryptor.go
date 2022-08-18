package kms

import (
	"flag"
	"github.com/cossacklabs/acra/keystore"
	baseKMS "github.com/cossacklabs/acra/keystore/kms/base"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/cossacklabs/acra/keystore/v2/keystore/crypto"
	log "github.com/sirupsen/logrus"
)

type (
	// KeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `kms_encrypted_master_key` strategy
	KeyEncryptorFabric struct{}
	// PerClientKeyEncryptorFabric implementation of keyloader.KeyEncryptorFabric for `kms_per_client` strategy
	PerClientKeyEncryptorFabric struct{}
)

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `kms_encrypted_master_key` strategy
func (k KeyEncryptorFabric) NewKeyEncryptor(flags *flag.FlagSet, prefix string) (keystore.KeyEncryptor, error) {
	kmsOptions := ParseCLIParametersFromFlags(flags, prefix)

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

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `kms_encrypted_master_key` strategy
func (k KeyEncryptorFabric) NewKeyEncryptorSuite(flags *flag.FlagSet, prefix string) (*crypto.KeyStoreSuite, error) {
	kmsOptions := ParseCLIParametersFromFlags(flags, prefix)

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

// RegisterCLIParameters empty implementation of KeyEncryptorFabric interface
func (k KeyEncryptorFabric) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	RegisterCLIParametersWithFlags(flags, prefix, description)
}

// NewKeyEncryptor fabric of keystore.KeyEncryptor for `kms_per_client` strategy
func (k PerClientKeyEncryptorFabric) NewKeyEncryptor(flags *flag.FlagSet, prefix string) (keystore.KeyEncryptor, error) {
	kmsOptions := ParseCLIParametersFromFlags(flags, prefix)

	keyManager, err := NewKeyManager(kmsOptions)
	if err != nil {
		log.WithError(err).Errorln("Cannot initialize kms KeyManager")
		return nil, err
	}
	return baseKMS.NewKeyEncryptor(keyManager), nil
}

// NewKeyEncryptorSuite fabric of crypto.KeyStoreSuite for `kms_per_client` strategy
func (k PerClientKeyEncryptorFabric) NewKeyEncryptorSuite(flags *flag.FlagSet, prefix string) (*crypto.KeyStoreSuite, error) {
	kmsOptions := ParseCLIParametersFromFlags(flags, prefix)

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
	return crypto.NewSCellSuiteWithEncryptor(baseKMS.NewKeyEncryptor(keyManager), signature)
}

// RegisterCLIParameters empty implementation of KeyEncryptorFabric interface
func (k PerClientKeyEncryptorFabric) RegisterCLIParameters(flags *flag.FlagSet, prefix, description string) {
	RegisterCLIParametersWithFlags(flags, prefix, description)
}
