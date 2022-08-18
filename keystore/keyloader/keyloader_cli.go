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

// RegisterCLIParametersWithFlagSet keyloader related flags
func RegisterCLIParametersWithFlagSet(flags *flag.FlagSet, prefix, description string) {
	if description != "" {
		description = " (" + description + ")"
	}

	if flags.Lookup(prefix+"keystore_encryption_type") == nil {
		flags.String(prefix+"keystore_encryption_type", KeystoreStrategyEnvMasterKey, fmt.Sprintf("Keystore encryptor strategy: <%s", strings.Join(SupportedKeystoreStrategies, "|")+description))
	}
}

// ParseCLIOptions parse registered flag.CommandLine CLIOptions
func ParseCLIOptions() *CLIOptions {
	return ParseCLIOptionsFromFlags(flag.CommandLine, "")
}

// ParseCLIOptionsFromFlags parse registered CLIOptions
func ParseCLIOptionsFromFlags(flags *flag.FlagSet, prefix string) *CLIOptions {
	options := CLIOptions{}

	if f := flags.Lookup(prefix + "keystore_encryption_type"); f != nil {
		options.KeystoreEncryptorType = f.Value.String()
	}
	return &options
}
