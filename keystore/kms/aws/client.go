package aws

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	baseKMS "github.com/cossacklabs/acra/keystore/kms"
)

// Configuration represent configuration file structure for AWS KMS
type Configuration struct {
	AccessKeyID     string  `json:"access_key_id"`
	SecretAccessKey string  `json:"secret_access_key"`
	Region          string  `json:"region"`
	Endpoint        *string `json:"endpoint,omitempty"`
}

// KMSClient represent general AWS KMS client
type KMSClient struct {
	client *kms.Client
}

// NewKMSClient create new KMS AWS client
func NewKMSClient(cfg *Configuration) (*KMSClient, error) {
	client, err := newKmsClient(cfg)
	if err != nil {
		return nil, err
	}

	return &KMSClient{
		client,
	}, nil
}

// Encrypt AWS KMS Encrypt call
func (e *KMSClient) Encrypt(ctx context.Context, keyID string, data []byte, context map[string]string) ([]byte, error) {
	input := &kms.EncryptInput{
		KeyId:             aws.String(keyID),
		Plaintext:         data,
		EncryptionContext: context,
	}

	result, err := e.client.Encrypt(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.CiphertextBlob, nil
}

// Decrypt AWS KMS Decrypt call
func (e *KMSClient) Decrypt(ctx context.Context, keyID string, blob []byte, context map[string]string) ([]byte, error) {
	input := &kms.DecryptInput{
		CiphertextBlob:    blob,
		KeyId:             aws.String(keyID),
		EncryptionContext: context,
	}

	result, err := e.client.Decrypt(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.Plaintext, nil
}

// CreateKey create KMS KEK with provided metadata
func (e *KMSClient) CreateKey(ctx context.Context, keyMetadata baseKMS.CreateKeyMetadata) (*types.KeyMetadata, error) {
	input := &kms.CreateKeyInput{
		Description: aws.String(keyMetadata.Description),
	}

	result, err := e.client.CreateKey(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.KeyMetadata, nil
}

// CreateAlias create alias for provided KeyID
func (e *KMSClient) CreateAlias(ctx context.Context, keyID, aliasName string) error {
	input := &kms.CreateAliasInput{
		AliasName:   aws.String(getAliasedName(aliasName)),
		TargetKeyId: aws.String(keyID),
	}

	_, err := e.client.CreateAlias(ctx, input)
	if err != nil {
		return err
	}

	return nil
}

// ListAliases list all available KMS key aliases in different regions
func (e *KMSClient) ListAliases(ctx context.Context, keyID *string) ([]types.AliasListEntry, error) {
	input := &kms.ListAliasesInput{}
	if keyID != nil {
		input.KeyId = keyID
	}

	aliases := make([]types.AliasListEntry, 0)
	for {
		result, err := e.client.ListAliases(ctx, input)
		if err != nil {
			return nil, err
		}

		aliases = append(aliases, result.Aliases...)
		if result.NextMarker == nil {
			break
		}
		input.Marker = result.NextMarker
	}

	return aliases, nil
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

	if configuration.Endpoint != nil {
		loadOptions = append(loadOptions,
			config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: *configuration.Endpoint}, nil
				})))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(cfg), nil
}
