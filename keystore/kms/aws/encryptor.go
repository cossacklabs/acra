package aws

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Configuration represent configuration file structure for AWS KMS
type Configuration struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region"`
}

// KeyIdentifierPrefix describe prefix used for AWS KMS KeyID
const KeyIdentifierPrefix = "aws-kms:"

// Encryptor implementation of AWS kms.Encryptor
type Encryptor struct {
	client *kms.Client
}

// NewEncryptor create new AWS KMS encryptor which implement kms.Encryptor interface
func NewEncryptor(credentialPath string) (*Encryptor, error) {
	configuration, err := readConfigByPath(credentialPath)
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(configuration.Region),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     configuration.AccessKeyID,
				SecretAccessKey: configuration.SecretAccessKey,
			}},
		))
	if err != nil {
		return nil, err
	}

	return &Encryptor{
		client: kms.NewFromConfig(cfg),
	}, nil
}

// Source return info about kms BE
func (e *Encryptor) Source() string {
	return "KMS AWS"
}

// Encrypt implementation of kms.Encryptor method
func (e *Encryptor) Encrypt(keyID string, data []byte) ([]byte, error) {
	input := &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: data,
	}

	result, err := e.client.Encrypt(context.Background(), input)
	if err != nil {
		return nil, err
	}

	return result.CiphertextBlob, nil
}

// Decrypt implementation of kms.Encryptor method
func (e *Encryptor) Decrypt(keyID string, blob []byte) ([]byte, error) {
	input := &kms.DecryptInput{
		CiphertextBlob: blob,
		KeyId:          aws.String(keyID),
	}

	result, err := e.client.Decrypt(context.Background(), input)
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
