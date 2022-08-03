package kms

import (
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/keystore/kms"
	"strings"

	"github.com/cossacklabs/acra/keystore/keyloader"
	log "github.com/sirupsen/logrus"
)

// AcraMasterKeyKEKID represent ID/alias of encryption key used for MasterKey loading
const AcraMasterKeyKEKID = "acra_master_key"

// TypeAWS supported KMS type AWS
const TypeAWS = "aws"

// supportedTypes contains all possible values for flag `--kms_type`
var supportedTypes = []string{
	TypeAWS,
}

// KeyPolicyCreate represent KMS key policy
const KeyPolicyCreate = "create"

// SupportedPolicies contains all possible values for flag `--kms_key_policy`
var SupportedPolicies = []string{
	KeyPolicyCreate,
}

// CLIOptions keep command-line options related to KMS ACRA_MASTER_KEY loading.
type CLIOptions struct {
	KMSType              string
	CredentialsPath      string
	KeyPolicy            string
	KMSKeystoreEncryptor bool
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
	if flags.Lookup(prefix+"kms_type") == nil {
		flags.StringVar(&options.KMSType, prefix+"kms_type", "", fmt.Sprintf("KMS type for using: <%s>", strings.Join(supportedTypes, "|")+description))
		// TODO: how to better provide an example of configuration files for different providers
		flags.StringVar(&options.CredentialsPath, prefix+"kms_credentials_path", "", "KMS credentials JSON file path"+description)
		flags.StringVar(&options.CredentialsPath, "kms_key_policy", KeyPolicyCreate, fmt.Sprintf("KMS usage key policy: <%s>", strings.Join(SupportedPolicies, "|")))
		flags.BoolVar(&options.KMSKeystoreEncryptor, "kms_keystore_encryptor", false, "Use KMS for keystore encryption")
	}
}

// GetCLIParameters returns a copy of CLIOptions parsed from the command line.
func GetCLIParameters() *CLIOptions {
	return &cliOptions
}

// New create MasterKeyLoader from kms.CLIOptions - implementation of keyloader.CliMasterKeyLoaderCreator interface
func (options CLIOptions) New() (keyloader.MasterKeyLoader, error) {
	if options.KMSType == "" {
		return nil, nil
	}

	keyManager, err := options.NewKeyManager()
	if err != nil {
		return nil, err
	}

	log.Infoln("Using KMS for ACRA_MASTER_KEY loading...")
	return NewLoader(keyManager), nil
}

// NewKeyManager create kms.KeyManager from kms.CLIOptions
func (options *CLIOptions) NewKeyManager() (kms.KeyManager, error) {
	createKeyManager, ok := kms.GetKeyManagerCreator(options.KMSType)
	if !ok {
		log.Errorf("Unknown KMS type provided %s", options.KMSType)
		return nil, nil
	}

	keyManager, err := createKeyManager(options.CredentialsPath)
	if err != nil {
		return nil, err
	}

	log.Infof("Initialized %s KeyManager", keyManager.ID())
	return keyManager, nil
}
