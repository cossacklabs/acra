package kms

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/keystore/kms/base"
	"github.com/cossacklabs/acra/utils/args"
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

// RegisterCLIParametersWithFlags register kms related flags
func RegisterCLIParametersWithFlags(flags *flag.FlagSet, prefix string, description string) {
	if description != "" {
		description = " (" + description + ")"
	}
	if flags.Lookup(prefix+"kms_type") == nil {
		flags.String(prefix+"kms_type", "", fmt.Sprintf("KMS type for using: <%s>", strings.Join(supportedTypes, "|")+description))
		flags.String(prefix+"kms_credentials_path", "", "KMS credentials JSON file path"+description)
	}
}

// ParseCLIParameters parse CLIOptions from CommandLine flags
func ParseCLIParameters(extractor *args.ServiceExtractor) *CLIOptions {
	return ParseCLIParametersFromFlags(extractor, "")
}

// ParseCLIParametersFromFlags parse CLIOptions from provided FlagSet
func ParseCLIParametersFromFlags(extractor *args.ServiceExtractor, prefix string) *CLIOptions {
	return &CLIOptions{
		KMSType:         extractor.GetString(prefix+"kms_type", ""),
		CredentialsPath: extractor.GetString(prefix+"kms_credentials_path", ""),
	}
}

// NewKeyManager create kms.KeyManager from kms.CLIOptions
func NewKeyManager(options *CLIOptions) (base.KeyManager, error) {
	createKeyManager, ok := base.GetKeyManagerCreator(options.KMSType)
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
