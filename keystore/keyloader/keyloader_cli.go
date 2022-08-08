package keyloader

import (
	"flag"
	"fmt"
	"strings"

	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
)

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
func (options *CLIOptions) RegisterCLIParameters(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+"kms_type") == nil {
		flags.StringVar(&options.KeystoreEncryptorType, prefix+"keystore_encryption_type", KeystoreStrategyMasterKey, fmt.Sprintf("Keystore encryptor strategy; : <%s", strings.Join(SupportedKeystoreStrategies, "|")+description))
	}

	options.vaultOptions.RegisterCLIParameters(flags, prefix, description)
	options.kmsOptions.RegisterCLIParameters(flags, prefix, description)
}

// GetCLIParameters returns a copy of CLIOptions parsed from the command line.
func GetCLIParameters() *CLIOptions {
	return &cliOptions
}

// GetVaultCLIParameters returns a copy of VaultCLIOptions parsed from the command line.
func (options *CLIOptions) GetVaultCLIParameters() *hashicorp.VaultCLIOptions {
	return &options.vaultOptions
}

// GetKMSParameters returns a copy of CLIOptions parsed from the command line.
func (options *CLIOptions) GetKMSParameters() *kms.CLIOptions {
	return &options.kmsOptions
}
