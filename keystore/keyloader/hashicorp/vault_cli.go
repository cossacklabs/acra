package hashicorp

import (
	"crypto/tls"
	"errors"
	"flag"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils/args"
)

// ErrEmptyConnectionURL error displaying empty Hashicorp Vault connection URL
var ErrEmptyConnectionURL = errors.New("empty Hashicorp Vault connection URL provided")

const (
	defaultVaultSecretsPath   = "secret/"
	vaultConnectionStringFlag = "vault_connection_api_string"
)

// VaultCLIOptions keep command-line options related to HashiCorp Vault ACRA_MASTER_KEY loading.
type VaultCLIOptions struct {
	Address     string
	SecretsPath string
	EnableTLS   bool
	tlsConfig   *tls.Config
}

// RegisterCLIParametersWithFlagSet look up for vault_connection_api_string, if none exists, vault_connection_api_string and vault_secrets_path
// will be added to provided flags.
func RegisterCLIParametersWithFlagSet(flags *flag.FlagSet, prefix, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+vaultConnectionStringFlag) == nil {
		flags.String(prefix+vaultConnectionStringFlag, "", "Connection string (http://x.x.x.x:yyyy) for loading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.String(prefix+"vault_secrets_path", defaultVaultSecretsPath, "KV Secret Path (secret/) for reading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.Bool(prefix+"vault_tls_transport_enable", false, "Use TLS to encrypt transport with HashiCorp Vault"+description)
		flags.String(prefix+"vault_tls_ca_path", "", "Path to CA certificate for HashiCorp Vault certificate validation (deprecated since 0.94.0, use `vault_tls_client_ca`)"+description)
	}

	if flags.Lookup(prefix+network.ClientNameConstructorFunc()("vault", "cert", "")) == nil {
		network.RegisterTLSArgsForService(flags, true, prefix+"vault", network.ClientNameConstructorFunc())
	}
}

// ParseCLIParametersFromFlags VaultCLIOptions from provided FlagSet
func ParseCLIParametersFromFlags(extractor *args.ServiceExtractor, prefix string) *VaultCLIOptions {
	options := VaultCLIOptions{
		Address:     extractor.GetString(prefix+vaultConnectionStringFlag, ""),
		SecretsPath: extractor.GetString(prefix+"vault_secrets_path", ""),
		EnableTLS:   extractor.GetBool(prefix+"vault_tls_transport_enable", ""),
	}

	namerFunc := network.ClientNameConstructorFunc()
	//for backward compatibility check if both  --vault_tls_ca_path and --vault_tls_client_ca not passed
	if oldFlag := extractor.GetString(prefix+"vault_tls_ca_path", ""); oldFlag != "" {
		var newCAPathFlagValue string
		var newFlag string
		if newFlag = extractor.GetString(prefix+namerFunc("vault", "ca", ""), ""); newFlag != "" {
			newCAPathFlagValue = newFlag
		}

		if oldFlag != "" && newCAPathFlagValue != "" {
			log.Errorf("Flags `%s` (deprecated) and `%s` cant be provided simultaneously", "vault_tls_ca_path", oldFlag)
			os.Exit(1)
		}

		// if the value was passed by old flag inject as new one
		if oldFlag != "" && newCAPathFlagValue == "" {
			newFlag = oldFlag
		}
	}

	var tlsConfig *tls.Config
	if options.EnableTLS {
		vaultURL, err := url.ParseRequestURI(options.Address)
		if err != nil {
			log.WithError(err).WithField("address", options.Address).Fatalln("Invalid Vault address provided")
		}

		tlsConfig, err = network.NewTLSConfigByName(extractor, prefix+"vault", vaultURL.Host, network.ClientNameConstructorFunc())
		if err != nil {
			log.WithError(err).Fatalln("Failed to create Vault TLS config")
		}
	}
	options.tlsConfig = tlsConfig
	return &options
}

// VaultHTTPClient returns api.Config connection configuration
func (options *VaultCLIOptions) VaultHTTPClient() (*http.Client, error) {
	transport := cleanhttp.DefaultPooledTransport()
	client := &http.Client{
		Transport: transport,
	}

	if options.EnableTLS {
		transport.TLSHandshakeTimeout = 10 * time.Second
		transport.TLSClientConfig = options.tlsConfig
	}
	return client, nil
}

// NewMasterKeyLoader create MasterKeyLoader from VaultCLIOptions
func NewMasterKeyLoader(extractor *args.ServiceExtractor, prefix string) (*VaultLoader, error) {
	vaultOptions := ParseCLIParametersFromFlags(extractor, prefix)
	if vaultOptions.Address == "" {
		return nil, ErrEmptyConnectionURL
	}

	log.Infoln("Initializing connection to HashiCorp Vault for ACRA_MASTER_KEY loading")
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = vaultOptions.Address

	httpClient, err := vaultOptions.VaultHTTPClient()
	if err != nil {
		log.WithError(err).Errorln("Can't initialize HashiCorp Vault http client")
		return nil, err
	}

	vaultConfig.HttpClient = httpClient

	keyLoader, err := NewVaultLoader(vaultConfig, vaultOptions.SecretsPath)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize HashiCorp Vault loader")
		return nil, err
	}
	log.Infoln("Initialized HashiCorp Vault ACRA_MASTER_KEY loader")
	return keyLoader, nil
}
