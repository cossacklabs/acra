package filesystem

import (
	"flag"

	"github.com/cossacklabs/acra/cmd"
)

// CLIOptions keep command-line options related to Consul encryptor config loader.
type CLIOptions struct {
	EncryptorConfigFile string
}

// RegisterCLIParametersWithFlagSet look up for encryptor_config_file, if none exists
func RegisterCLIParametersWithFlagSet(flags *flag.FlagSet, prefix, description string) {
	if flags.Lookup(prefix+"encryptor_config_file") == nil {
		flag.String("encryptor_config_file", "", "Path to Encryptor configuration file")
	}
}

// ParseCLIParametersFromFlags VaultCLIOptions from provided FlagSet
func ParseCLIParametersFromFlags(extractor *cmd.ServiceParamsExtractor, prefix string) *CLIOptions {
	return &CLIOptions{
		EncryptorConfigFile: extractor.GetString(prefix+"encryptor_config_file", ""),
	}
}
