package consul

import (
	"flag"
	"strconv"

	"github.com/hashicorp/consul/api"
	log "github.com/sirupsen/logrus"
)

const defaultConsulConfiPath = "acra/encryptor_config"

// CLIOptions keep command-line options related to Consul encryptor config loader.
type CLIOptions struct {
	Address             string
	EncryptorConfigPath string
	CAPath              string
	ClientCert          string
	ClientKey           string
	EnableTLS           bool
}

// RegisterCLIParametersWithFlagSet look up for consul_connection_api_string, if none exists, consul_connection_api_string and consul_kv_config_path
// will be added to provided flags.
func RegisterCLIParametersWithFlagSet(flags *flag.FlagSet, prefix, description string) {
	if description != "" {
		description = " (" + description + ")"
	}

	if flags.Lookup(prefix+"consul_connection_api_string") == nil {
		flags.String(prefix+"consul_connection_api_string", "", "Connection string (http://x.x.x.x:yyyy)for loading encryptor config from HashiCorp Consul"+description)
		flags.String(prefix+"consul_kv_config_path", defaultConsulConfiPath, "KV Encryptor Config Path (acra/encryptor_config) for loading encryptor config from HashiCorp Consul"+description)
		flags.String(prefix+"consul_tls_ca_path", "", "Path to CA certificate for loading encryptor config from HashiCorp Consul"+description)
		flags.String(prefix+"consul_tls_client_cert", "", "Path to client TLS certificate for loading encryptor config from HashiCorp Consul"+description)
		flags.String(prefix+"consul_tls_client_key", "", "Path to private key of the client TLS certificate for loading encryptor config from HashiCorp Consul"+description)
		flags.Bool(prefix+"consul_tls_transport_enable", false, "Use TLS to encrypt transport with HashiCorp Consul"+description)
	}
}

// TLSConfig return TLS configuration needed to connect to HashiCorp Vault
func (options *CLIOptions) TLSConfig() api.TLSConfig {
	return api.TLSConfig{
		CertFile: options.ClientCert,
		KeyFile:  options.ClientKey,
		CAPath:   options.CAPath,
	}
}

// ParseCLIParametersFromFlags CLIOptions from provided FlagSet
func ParseCLIParametersFromFlags(flags *flag.FlagSet, prefix string) *CLIOptions {
	options := CLIOptions{}

	if f := flags.Lookup(prefix + "consul_connection_api_string"); f != nil {
		options.Address = f.Value.String()
	}

	if f := flags.Lookup(prefix + "consul_kv_config_path"); f != nil {
		options.EncryptorConfigPath = f.Value.String()
	}

	if f := flags.Lookup(prefix + "consul_tls_ca_path"); f != nil {
		options.CAPath = f.Value.String()
	}
	if f := flags.Lookup(prefix + "consul_tls_client_cert"); f != nil {
		options.ClientCert = f.Value.String()
	}
	if f := flags.Lookup(prefix + "consul_tls_client_key"); f != nil {
		options.ClientKey = f.Value.String()
	}
	if f := flags.Lookup(prefix + "consul_tls_transport_enable"); f != nil {
		val, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			log.WithField("value", f.Value.String()).Fatalf("Can't cast %s to bool value", prefix+"consul_tls_transport_enable")
		}
		options.EnableTLS = val
	}

	return &options
}
