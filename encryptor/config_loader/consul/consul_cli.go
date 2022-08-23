package consul

import (
	"flag"
)

const (
	defaultConsulConfiPath     = "acra/encryptor_config"
	consulConnectionStringFlag = "consul_connection_api_string"
)

// CLIOptions keep command-line options related to Consul encryptor config loader.
type CLIOptions struct {
	Address             string
	EncryptorConfigPath string
}

// RegisterCLIParametersWithFlagSet look up for consul_connection_api_string, if none exists, consul_connection_api_string and consul_kv_config_path
// will be added to provided flags.
func RegisterCLIParametersWithFlagSet(flags *flag.FlagSet, prefix, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	// TODO: add tls support
	if flags.Lookup(prefix+consulConnectionStringFlag) == nil {
		flags.String(prefix+consulConnectionStringFlag, "", "Connection string (http://x.x.x.x:yyyy) for loading encryptor config from Consul"+description)
		flags.String(prefix+"consul_kv_config_path", defaultConsulConfiPath, "KV Encryptor Config Path (acra/encryptor_config) for loading encryptor config from Consul"+description)
	}
}

// ParseCLIParametersFromFlags CLIOptions from provided FlagSet
func ParseCLIParametersFromFlags(flags *flag.FlagSet, prefix string) *CLIOptions {
	options := CLIOptions{}

	if f := flags.Lookup(prefix + consulConnectionStringFlag); f != nil {
		options.Address = f.Value.String()
	}

	if f := flags.Lookup(prefix + "consul_kv_config_path"); f != nil {
		options.EncryptorConfigPath = f.Value.String()
	}

	return &options
}
