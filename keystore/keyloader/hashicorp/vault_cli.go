package hashicorp

import (
	"flag"
	"github.com/hashicorp/vault/api"
)

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

var vaultOptions VaultCLIOptions

// RegisterVaultCLIParameters registers CLI parameters for reading ACRA_MASTER_KEY from HashiCorp Vault.
func RegisterVaultCLIParameters() {
	vaultOptions.RegisterCLIParameters(flag.CommandLine, "", "")
}

// RegisterCLIParameters look up for vault_connection_api_string, if none exists, vault_connection_api_string and vault_secrets_path
// will be added to provided flags.
func (options *VaultCLIOptions) RegisterCLIParameters(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+vaultConnectionStringFlag) == nil {
		flags.StringVar(&options.Address, prefix+vaultConnectionStringFlag, "", "Connection string (http://x.x.x.x:yyyy) for loading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.StringVar(&options.SecretsPath, prefix+"vault_secrets_path", defaultVaultSecretsPath, "KV Secret Path (secret/) for reading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.StringVar(&options.CAPath, prefix+"vault_tls_ca_path", "", "Path to CA certificate for HashiCorp Vault certificate validation"+description)
		flags.StringVar(&options.ClientCert, prefix+"vault_tls_client_cert", "", "Path to client TLS certificate for reading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.StringVar(&options.ClientKey, prefix+"vault_tls_client_key", "", "Path to private key of the client TLS certificate for reading ACRA_MASTER_KEY from HashiCorp Vault"+description)
		flags.BoolVar(&options.EnableTLS, prefix+"vault_tls_transport_enable", false, "Use TLS to encrypt transport with HashiCorp Vault"+description)
	}
}

//TLSConfig return TLS configuration needed to connect to HashiCorp Vault
func (options *VaultCLIOptions) TLSConfig() *api.TLSConfig {
	return &api.TLSConfig{
		ClientKey:  options.ClientKey,
		ClientCert: options.ClientCert,
		CAPath:     options.CAPath,
	}
}

// GetVaultCLIParameters returns a copy of VaultCLIOptions parsed from the command line.
func GetVaultCLIParameters() VaultCLIOptions {
	return vaultOptions
}
