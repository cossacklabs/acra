package keyloader

import (
	"flag"
	"fmt"
	"strings"
)

// represent all possible keystore strategies
const (
	KeystoreStrategyEnvMasterKey            = "env_master_key"
	KeystoreStrategyKMSMasterKey            = "kms_encrypted_master_key"
	KeystoreStrategyHashicorpVaultMasterKey = "vault_master_key"
	KeystoreStrategyKMSPerClient            = "kms_per_client"
)

// SupportedKeystoreStrategies contains all possible values for flag `--keystore_encryption_type`
var SupportedKeystoreStrategies = []string{
	KeystoreStrategyEnvMasterKey,
	KeystoreStrategyKMSMasterKey,
	KeystoreStrategyHashicorpVaultMasterKey,
	KeystoreStrategyKMSPerClient,
}

// CLIOptions keep command-line options related to KMS ACRA_MASTER_KEY loading.
type CLIOptions struct {
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
	if flags.Lookup(prefix+"keystore_encryption_type") == nil {
		flags.StringVar(&cli.KeystoreEncryptorType, prefix+"keystore_encryption_type", KeystoreStrategyEnvMasterKey, fmt.Sprintf("Keystore encryptor strategy: <%s", strings.Join(SupportedKeystoreStrategies, "|")+description))
	}
}

// GetCLIParameters returns a copy of CLIOptions parsed from the command line.
func GetCLIParameters() *CLIOptions {
	return &cliOptions
}
