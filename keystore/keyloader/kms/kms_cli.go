package kms

import (
	"flag"

	"github.com/cossacklabs/acra/keystore/keyloader"
	log "github.com/sirupsen/logrus"
)

const (
	kmsKeyURIFlag = "master_key_encryption_key_uri"
)

// CLIOptions keep command-line options related to KMS ACRA_MASTER_KEY loading.
type CLIOptions struct {
	KeyIdentifierURI string
	CredentialsPath  string
}

var cliOptions CLIOptions

// RegisterCLIParameters registers CLI parameters for reading ACRA_MASTER_KEY from KMS.
func RegisterCLIParameters() {
	cliOptions.RegisterCLIParameters(flag.CommandLine, "", "")
}

// RegisterCLIParameters look up for vault_connection_api_string, if none exists, vault_connection_api_string and vault_secrets_path
// will be added to provided flags.
func (options *CLIOptions) RegisterCLIParameters(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+kmsKeyURIFlag) == nil {
		flags.StringVar(&options.KeyIdentifierURI, prefix+kmsKeyURIFlag, "", "KMS Key identifier in Tink's format"+description)
		// TODO: how to better provide an example of configuration files for different providers
		flags.StringVar(&options.CredentialsPath, prefix+"kms_credentials_path", "", "KMS credentials JSON file path"+description)
	}
}

// GetCLIParameters returns a copy of CLIOptions parsed from the command line.
func GetCLIParameters() *CLIOptions {
	return &cliOptions
}

// New create MasterKeyLoader from kms.CLIOptions - implementation of keyloader.CliMasterKeyLoaderCreator interface
func (options *CLIOptions) New() (keyloader.MasterKeyLoader, error) {
	if options.KeyIdentifierURI == "" {
		return nil, nil
	}

	log.Infoln("Using KMS for ACRA_MASTER_KEY loading...")
	return NewLoader(options.CredentialsPath, options.KeyIdentifierURI)
}
