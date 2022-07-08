package aws

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	baseKMS "github.com/cossacklabs/acra/keystore/kms"
)

// Configuration represent configuration file structure for AWS KMS
type Configuration struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region"`
	Endpoint        string `json:"endpoint"`
}

// KeyIdentifierPrefix describe prefix used for AWS KMS KeyID
const KeyIdentifierPrefix = "aws-kms:"

// Encryptor implementation of AWS Encryptor
type Encryptor struct {
	client *kms.Client
}

// NewEncryptor create new AWS KMS encryptor which implement Encryptor interface
func NewEncryptor(credentialPath string) (baseKMS.Encryptor, error) {
	configuration, err := readConfigByPath(credentialPath)
	if err != nil {
		return nil, err
	}

	client, err := newKmsClient(configuration)
	if err != nil {
		return nil, err
	}

	return &Encryptor{client}, nil
}

// ID return info about kms BE
func (e *Encryptor) ID() string {
	return "KMS AWS"
}

// Encrypt implementation of kms.Encryptor method
func (e *Encryptor) Encrypt(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	input := &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: data,
	}

	result, err := e.client.Encrypt(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.CiphertextBlob, nil
}

// Decrypt implementation of kms.Encryptor method
func (e *Encryptor) Decrypt(ctx context.Context, keyID string, blob []byte) ([]byte, error) {
	input := &kms.DecryptInput{
		CiphertextBlob: blob,
		KeyId:          aws.String(keyID),
	}

	result, err := e.client.Decrypt(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.Plaintext, nil
}

func readConfigByPath(credentialPath string) (*Configuration, error) {
	creds, err := ioutil.ReadFile(credentialPath)
	if err != nil {
		return nil, err
	}

	configuration := Configuration{}
	err = json.Unmarshal(creds, &configuration)
	return &configuration, err
}

func newKmsClient(configuration *Configuration) (*kms.Client, error) {
	loadOptions := []func(options *config.LoadOptions) error{
		config.WithRegion(configuration.Region),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     configuration.AccessKeyID,
				SecretAccessKey: configuration.SecretAccessKey,
			}}),
	}

	if configuration.Endpoint != "" {
		loadOptions = append(loadOptions,
			config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: configuration.Endpoint}, nil
				})))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(cfg), nil
}

func init() {
	baseKMS.RegisterEncryptorCreator(KeyIdentifierPrefix, NewEncryptor)
}
