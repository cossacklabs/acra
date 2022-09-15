package hashicorp

import (
	"crypto/tls"
	"errors"
	"flag"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/cossacklabs/acra/network"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// ErrEmptyConnectionURL error displaying empty Hashicorp Vault connection URL
var ErrEmptyConnectionURL = errors.New("empty Hashicorp Vault connection URL provided")

const (
	defaultVaultSecretsPath   = "secret/"
	vaultConnectionStringFlag = "vault_connection_api_string"
)

// VaultCLIOptions keep command-line options related to HashiCorp Vault ACRA_MASTER_KEY loading.
type VaultCLIOptions struct {
	Address      string
	SecretsPath  string
	CAPath       string
	ClientCert   string
	ClientKey    string
	SNI          string
	CertVerifier network.CertVerifier
	Auth         tls.ClientAuthType
	EnableTLS    bool
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
func ParseCLIParametersFromFlags(flags *flag.FlagSet, prefix string) *VaultCLIOptions {
	options := VaultCLIOptions{}

	if f := flags.Lookup(prefix + vaultConnectionStringFlag); f != nil {
		options.Address = f.Value.String()
	}
	if f := flags.Lookup(prefix + "vault_secrets_path"); f != nil {
		options.SecretsPath = f.Value.String()
	}
	if f := flags.Lookup(prefix + "vault_tls_ca_path"); f != nil {
		options.CAPath = f.Value.String()
	}
	if f := flags.Lookup(prefix + "vault_tls_transport_enable"); f != nil {
		val, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			log.WithField("value", f.Value.String()).Fatalf("Can't cast %s to bool value", f.Name)
		}
		options.EnableTLS = val
	}

	namerFunc := network.ClientNameConstructorFunc()
	if f := flags.Lookup(namerFunc("vault", "ca", "")); f != nil {
		newCAPathFlagValue := f.Value.String()
		if options.CAPath != "" && newCAPathFlagValue != "" {
			log.Errorf("Flags `%s` (deprecated) and `%s` cant be provided simultaneously", "vault_tls_ca_path", f.Name)
			os.Exit(1)
		}

		if newCAPathFlagValue != "" {
			options.CAPath = f.Value.String()
		}
	}
	if f := flags.Lookup(namerFunc("vault", "sni", "")); f != nil {
		options.SNI = f.Value.String()
	}
	if f := flags.Lookup(namerFunc("vault", "cert", "")); f != nil {
		options.ClientCert = f.Value.String()
	}
	if f := flags.Lookup(namerFunc("vault", "key", "")); f != nil {
		options.ClientKey = f.Value.String()
	}
	if f := flags.Lookup(namerFunc("vault", "auth", "")); f != nil {
		v, err := strconv.ParseInt(f.Value.String(), 10, 64)
		if err != nil {
			log.WithField("value", f.Value.String).Fatalf("Can't cast %s to integer value", f.Name)
		}
		options.Auth = tls.ClientAuthType(v)
	}

	var err error
	ocspConfig, err := network.NewOCSPConfigByName(flags, "vault", namerFunc)
	if err != nil {
		log.WithError(err).Fatalf("Can't parse Vault OCSPConfig")
	}
	crlConfig, err := network.NewCRLConfigByName(flags, "vault", namerFunc)
	if err != nil {
		log.WithError(err).Fatalf("Can't parse Vault CRLConfig")
	}
	options.CertVerifier, err = network.NewCertVerifierFromConfigs(ocspConfig, crlConfig)
	if err != nil {
		log.WithError(err).Fatalf("Can't parse Vault CertVerifier")
	}

	return &options
}

// VaultHTTPClient returns api.Config connection configuration
func (options *VaultCLIOptions) VaultHTTPClient() (*http.Client, error) {
	transport := cleanhttp.DefaultPooledTransport()
	client := &http.Client{
		Transport: transport,
	}

	vaultURL, err := url.ParseRequestURI(options.Address)
	if err != nil {
		log.WithError(err).WithField("address", options.Address).Errorln("Invalid Vault address provided")
		return nil, err
	}

	if options.EnableTLS {
		serverName := network.SNIOrHostname(options.SNI, vaultURL.Host)
		tlsConfig, err := network.NewTLSConfig(serverName, options.CAPath, options.ClientKey, options.ClientCert, options.Auth, options.CertVerifier)
		if err != nil {
			return nil, err
		}

		transport.TLSHandshakeTimeout = 10 * time.Second
		transport.TLSClientConfig = tlsConfig
	}
	return client, nil
}

// NewMasterKeyLoader create MasterKeyLoader from VaultCLIOptions
func NewMasterKeyLoader(flags *flag.FlagSet, prefix string) (*VaultLoader, error) {
	vaultOptions := ParseCLIParametersFromFlags(flags, prefix)
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
