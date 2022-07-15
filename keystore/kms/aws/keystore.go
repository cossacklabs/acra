package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	baseKMS "github.com/cossacklabs/acra/keystore/kms"
)

// Keystore implementation of AWS Keystore
type Keystore struct {
	cfg    *Configuration
	client *KMSClient
}

// NewKeystore create new AWS KMS encryptor which implement Keystore interface
func NewKeystore(credentialPath string) (baseKMS.Keystore, error) {
	cfg, err := readConfigByPath(credentialPath)
	if err != nil {
		return nil, err
	}

	client, err := NewKmsClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Keystore{cfg, client}, nil
}

// ID return source of
func (k *Keystore) ID() string {
	return "KMS AWS"
}

// CreateKey create key on KMS according to specification
func (k *Keystore) CreateKey(ctx context.Context, metaData baseKMS.CreateKeyMetadata) (*baseKMS.KeyMetadata, error) {
	keyMetadata, err := k.client.CreateKey(ctx, metaData)
	if err != nil {
		return nil, err
	}

	if err := k.client.CreateAlias(ctx, *keyMetadata.Arn, metaData.KeyName); err != nil {
		return nil, err
	}

	return &baseKMS.KeyMetadata{
		KeyID: *keyMetadata.Arn,
	}, nil
}

// IsKeyExist check if key is present on KMS
func (k *Keystore) IsKeyExist(ctx context.Context, keyID string) (bool, error) {
	aliases, err := k.client.ListAliases(ctx, nil)
	if err != nil {
		return false, err
	}

	for _, alias := range aliases {
		// format of ARN is arn:aws:kms:eu-west-1:account-id:alias/acra-master-key-test
		arnParts := strings.Split(*alias.AliasArn, ":")
		if len(arnParts) < 6 {
			return false, errors.New("invalid arn format found for keyId")
		}
		region := arnParts[3]

		if *alias.AliasName == fmt.Sprintf("alias/%s", keyID) && region == k.cfg.Region {
			return true, nil
		}
	}

	return false, nil
}

// Encrypt implementation of kms.Encryptor method
func (k *Keystore) Encrypt(ctx context.Context, keyID []byte, data []byte, context []byte) ([]byte, error) {
	var encryptionContext map[string]string
	if context != nil {
		//  set encryption context in case of provided additional authenticated data
		encryptionContext = map[string]string{"context": string(context)}
	}

	return k.client.Encrypt(ctx, fmt.Sprintf("alias/%s", keyID), data, encryptionContext)
}

// Decrypt implementation of kms.Encryptor method
func (k *Keystore) Decrypt(ctx context.Context, keyID []byte, blob []byte, context []byte) ([]byte, error) {
	var encryptionContext map[string]string
	if context != nil {
		//  set encryption context in case of provided additional authenticated data
		encryptionContext = map[string]string{"context": string(context)}
	}

	return k.client.Decrypt(ctx, fmt.Sprintf("alias/%s", keyID), blob, encryptionContext)
}
