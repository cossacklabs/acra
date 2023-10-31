package keyloader

import (
	"flag"
	"fmt"
	"strings"

	"github.com/cossacklabs/acra/cmd"
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
func ParseCLIOptions(extractor *cmd.ServiceParamsExtractor) *CLIOptions {
	return ParseCLIOptionsFromFlags(extractor, "")
}

// ParseCLIOptionsFromFlags parse registered CLIOptions
func ParseCLIOptionsFromFlags(extractor *cmd.ServiceParamsExtractor, prefix string) *CLIOptions {
	return &CLIOptions{
		KeystoreEncryptorType: extractor.GetString(prefix+"keystore_encryption_type", ""),
	}
}
