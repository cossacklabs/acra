package consul

import (
	"flag"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cossacklabs/acra/network"
	"github.com/hashicorp/go-cleanhttp"
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

		flags.Bool(prefix+"consul_tls_enable", false, "Use TLS to encrypt transport with HashiCorp Consul"+description)
	}

	if flags.Lookup(prefix+network.ClientNameConstructorFunc()("consul", "cert", "")) == nil {
		network.RegisterTLSArgsForService(flags, true, prefix+"consul", network.ClientNameConstructorFunc())
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

	if f := flags.Lookup(prefix + "consul_tls_enable"); f != nil {
		val, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			log.WithField("value", f.Value.String()).Fatalf("Can't cast %s to bool value", prefix+"consul_tls_enable")
		}
		options.EnableTLS = val
	}

	return &options
}

// ConsulHttpClient returns api.Config connection configuration
func (consul *CLIOptions) ConsulHttpClient(flags *flag.FlagSet) (*http.Client, error) {
	transport := cleanhttp.DefaultPooledTransport()
	client := &http.Client{
		Transport: transport,
	}

	consulURL, err := url.ParseRequestURI(consul.Address)
	if err != nil {
		log.WithError(err).WithField("address", consul.Address).Errorln("Invalid Consul address provided")
		return nil, err
	}

	if consul.EnableTLS {
		tlsConfig, err := network.NewTLSConfigByName(flags, "consul", consulURL.Host, network.ClientNameConstructorFunc())
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	return client, nil
}
