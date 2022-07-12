package kms

import (
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/keystore/kms"
	"strings"

	"github.com/cossacklabs/acra/keystore/keyloader"
	log "github.com/sirupsen/logrus"
)

const kmsTypeFlag = "kms_type"

// CLIOptions keep command-line options related to KMS ACRA_MASTER_KEY loading.
type CLIOptions struct {
	KMSType         string
	CredentialsPath string
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
	if flags.Lookup(prefix+kmsTypeFlag) == nil {
		flags.StringVar(&options.KMSType, prefix+kmsTypeFlag, "", fmt.Sprintf("KMS type for using: <%s>", strings.Join(kms.SupportedTypes, "|")+description))
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
	if options.KMSType == "" {
		return nil, nil
	}

	log.Infoln("Using KMS for ACRA_MASTER_KEY loading...")
	return NewLoader(options.CredentialsPath, options.KMSType)
}
