package hashicorp

import (
	"errors"
	"flag"
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
	Address     string
	SecretsPath string
	CAPath      string
	ClientCert  string
	ClientKey   string
	EnableTLS   bool
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
		flags.String(prefix+"vault_tls_ca_path", "", "Path to CA certificate for HashiCorp Vault certificate validation"+description)
		flags.String(prefix+"vault_tls_client_cert", "", "Path to client TLS certificate for reading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.String(prefix+"vault_tls_client_key", "", "Path to private key of the client TLS certificate for reading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.Bool(prefix+"vault_tls_transport_enable", false, "Use TLS to encrypt transport with HashiCorp Vault"+description)
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
	if f := flags.Lookup(prefix + "vault_tls_client_cert"); f != nil {
		options.ClientCert = f.Value.String()
	}
	if f := flags.Lookup(prefix + "vault_tls_client_key"); f != nil {
		options.ClientKey = f.Value.String()
	}
	if f := flags.Lookup(prefix + "vault_tls_transport_enable"); f != nil {
		getter, ok := f.Value.(flag.Getter)
		if !ok {
			log.Fatal("Can't cast flag's Value to Getter")
		}
		val, ok := getter.Get().(bool)
		if !ok {
			log.WithField("value", getter.Get()).Fatalf("Can't cast %s to bool value", prefix+"vault_tls_transport_enable")
		}
		options.EnableTLS = val
	}

	return &options
}

// TLSConfig return TLS configuration needed to connect to HashiCorp Vault
func (options *VaultCLIOptions) TLSConfig() *api.TLSConfig {
	return &api.TLSConfig{
		ClientKey:  options.ClientKey,
		ClientCert: options.ClientCert,
		CAPath:     options.CAPath,
	}
}

// NewMasterKeyLoader create MasterKeyLoader from VaultCLIOptions
func NewMasterKeyLoader(options *VaultCLIOptions) (*VaultLoader, error) {
	if options.Address == "" {
		return nil, ErrEmptyConnectionURL
	}

	log.Infoln("Initializing connection to HashiCorp Vault for ACRA_MASTER_KEY loading")
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = options.Address

	if options.EnableTLS {
		log.Infoln("Configuring TLS connection to HashiCorp Vault")

		if err := vaultConfig.ConfigureTLS(options.TLSConfig()); err != nil {
			return nil, err
		}
	}

	keyLoader, err := NewVaultLoader(vaultConfig, options.SecretsPath)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize HashiCorp Vault loader")
		return nil, err
	}
	log.Infoln("Initialized HashiCorp Vault ACRA_MASTER_KEY loader")
	return keyLoader, nil
}
