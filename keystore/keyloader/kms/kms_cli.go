package kms

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/cossacklabs/acra/keystore/kms"
	log "github.com/sirupsen/logrus"
)

// ErrUnknownKMSType error displaying unknown KMS type provided by flags
var ErrUnknownKMSType = errors.New("unknown KMS type provided")

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
	KMSType         string
	CredentialsPath string
}

// RegisterCLIParameters look up for vault_connection_api_string, if none exists, vault_connection_api_string and vault_secrets_path
// will be added to provided flags.
func (options *CLIOptions) RegisterCLIParameters(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+"kms_type") == nil {
		flags.StringVar(&options.KMSType, prefix+"kms_type", "", fmt.Sprintf("KMS type for using: <%s>", strings.Join(supportedTypes, "|")+description))
		flags.StringVar(&options.CredentialsPath, prefix+"kms_credentials_path", "", "KMS credentials JSON file path"+description)
	}
}

// NewKeyManager create kms.KeyManager from kms.CLIOptions
func (options *CLIOptions) NewKeyManager() (kms.KeyManager, error) {
	createKeyManager, ok := kms.GetKeyManagerCreator(options.KMSType)
	if !ok {
		log.Errorf("Unknown KMS type provided %s", options.KMSType)
		return nil, ErrUnknownKMSType
	}

	keyManager, err := createKeyManager(options.CredentialsPath)
	if err != nil {
		return nil, err
	}

	log.Infof("Initialized %s KeyManager", keyManager.ID())
	return keyManager, nil
}
