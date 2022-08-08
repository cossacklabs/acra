package keyloader

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// ErrEmptyConnectionURL error displaying empty Hashicorp Vault connection URL
var ErrEmptyConnectionURL = errors.New("empty Hashicorp Vault connection URL provided")

// represent all possible keyloader strategies
const (
	KeystoreStrategyMasterKey               = "master_key"
	KeystoreStrategyKMSMasterKey            = "kms_encrypted_master_key"
	KeystoreStrategyHashicorpVaultMasterKey = "vault_master_key"
	KeystoreStrategyKMSPerClient            = "kms_per_client"
)

// SupportedKeystoreStrategies contains all possible values for flag `--keystore_encryption_type`
var SupportedKeystoreStrategies = []string{
	KeystoreStrategyMasterKey,
	KeystoreStrategyKMSMasterKey,
	KeystoreStrategyHashicorpVaultMasterKey,
	KeystoreStrategyKMSPerClient,
}

// CLIOptions keep command-line options related to KMS ACRA_MASTER_KEY loading.
type CLIOptions struct {
	kmsOptions            kms.CLIOptions
	vaultOptions          hashicorp.VaultCLIOptions
	KeystoreEncryptorType string
}

var cliOptions CLIOptions

// RegisterCLIParameters registers CLI parameters for reading ACRA_MASTER_KEY from KMS.
func RegisterCLIParameters() {
	cliOptions.RegisterCLIParameters(flag.CommandLine, "", "")
}

// RegisterCLIParameters look up for vault_connection_api_string, if none exists, vault_connection_api_string and vault_secrets_path
// will be added to provided flags.
func (cli *CLIOptions) RegisterCLIParameters(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+"kms_type") == nil {
		flags.StringVar(&cli.KeystoreEncryptorType, prefix+"keystore_encryption_type", KeystoreStrategyMasterKey, fmt.Sprintf("Keystore encryptor strategy; : <%s", strings.Join(SupportedKeystoreStrategies, "|")+description))
	}

	cli.vaultOptions.RegisterCLIParameters(flags, prefix, description)
	cli.kmsOptions.RegisterCLIParameters(flags, prefix, description)
}

// GetCLIParameters returns a copy of CLIOptions parsed from the command line.
func GetCLIParameters() *CLIOptions {
	return &cliOptions
}

// GetVaultCLIParameters returns a copy of VaultCLIOptions parsed from the command line.
func (cli *CLIOptions) GetVaultCLIParameters() *hashicorp.VaultCLIOptions {
	return &cli.vaultOptions
}

// GetKMSParameters returns a copy of CLIOptions parsed from the command line.
func (cli *CLIOptions) GetKMSParameters() *kms.CLIOptions {
	return &cli.kmsOptions
}

// NewVaultMasterKeyLoader returns a copy of VaultCLIOptions parsed from the command line.
func NewVaultMasterKeyLoader(vaultOptions *hashicorp.VaultCLIOptions) (MasterKeyLoader, error) {
	if vaultOptions.Address == "" {
		return nil, ErrEmptyConnectionURL
	}

	log.Infoln("Initializing connection to HashiCorp Vault for ACRA_MASTER_KEY loading")
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = vaultOptions.Address

	if vaultOptions.EnableTLS {
		log.Infoln("Configuring TLS connection to HashiCorp Vault")

		if err := vaultConfig.ConfigureTLS(vaultOptions.TLSConfig()); err != nil {
			return nil, err
		}
	}

	keyLoader, err := hashicorp.NewVaultLoader(vaultConfig, vaultOptions.SecretsPath)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize HashiCorp Vault loader")
		return nil, err
	}
	log.Infoln("Initialized Hashicorp Vault ACRA_MASTER_KEY loader")
	return keyLoader, nil
}

// NewKMSMasterKeyLoader returns a copy of CLIOptions parsed from the command line.
func NewKMSMasterKeyLoader(kmsOptions *kms.CLIOptions) (MasterKeyLoader, error) {
	keyManager, err := kmsOptions.NewKeyManager()
	if err != nil {
		return nil, err
	}

	log.Infoln("Using KMS for ACRA_MASTER_KEY loading...")
	return kms.NewLoader(keyManager), nil
}
