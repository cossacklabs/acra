package consul

import (
	"flag"
	"net/http"
	"net/url"

	"github.com/hashicorp/go-cleanhttp"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/network"
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
func ParseCLIParametersFromFlags(extractor *cmd.ServiceParamsExtractor, prefix string) *CLIOptions {
	return &CLIOptions{
		Address:             extractor.GetString(prefix+"consul_connection_api_string", ""),
		EncryptorConfigPath: extractor.GetString(prefix+"consul_kv_config_path", prefix),
		EnableTLS:           extractor.GetBool(prefix+"consul_tls_enable", ""),
	}
}

// ConsulHTTPClient returns api.Config connection configuration
func (consul *CLIOptions) ConsulHTTPClient(extractor *cmd.ServiceParamsExtractor) (*http.Client, error) {
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
		tlsConfig, err := network.NewTLSConfigByName(extractor, "consul", consulURL.Host, network.ClientNameConstructorFunc())
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	return client, nil
}
