package aws

import (
	"context"
	"errors"
	"strings"
	"time"

	baseKMS "github.com/cossacklabs/acra/keystore/kms/base"
)

// KeyManager is AWS implementation of kms.KeyManager
type KeyManager struct {
	cfg    *Configuration
	client *KMSClient
}

// NewKeyManager create new AWS KeyManager which implement kms.KeyManager interface
func NewKeyManager(credentialPath string) (baseKMS.KeyManager, error) {
	cfg, err := readConfigByPath(credentialPath)
	if err != nil {
		return nil, err
	}

	client, err := NewKMSClient(cfg)
	if err != nil {
		return nil, err
	}
	return &KeyManager{cfg, client}, nil
}

// ID return source of
func (k *KeyManager) ID() string {
	return "KMS AWS"
}

// CreateKey create key on KMS according to specification
func (k *KeyManager) CreateKey(ctx context.Context, metaData baseKMS.CreateKeyMetadata) (*baseKMS.KeyMetadata, error) {
	keyMetadata, err := k.client.CreateKey(ctx, metaData)
	if err != nil {
		return nil, err
	}

	if err := k.client.CreateAlias(ctx, *keyMetadata.Arn, metaData.KeyName); err != nil {
		return nil, err
	}

	// wait some time for alias to be active
	for {
		keyExist, err := k.IsKeyExist(ctx, metaData.KeyName)
		if err != nil {
			return nil, err
		}

		if keyExist {
			return &baseKMS.KeyMetadata{
				KeyID: *keyMetadata.Arn,
			}, nil
		}
		time.Sleep(time.Millisecond * 100)
	}
}

// IsKeyExist check if key is present on KMS
func (k *KeyManager) IsKeyExist(ctx context.Context, keyID string) (bool, error) {
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

		if *alias.AliasName == getAliasedName(keyID) && region == k.cfg.Region {
			return true, nil
		}
	}

	return false, nil
}

// Encrypt implementation of kms.Encryptor method
func (k *KeyManager) Encrypt(ctx context.Context, keyID []byte, data []byte, context []byte) ([]byte, error) {
	var encryptionContext map[string]string
	if context != nil {
		//  set encryption context in case of provided additional authenticated data
		encryptionContext = map[string]string{"context": string(context)}
	}

	return k.client.Encrypt(ctx, getAliasedName(string(keyID)), data, encryptionContext)
}

// Decrypt implementation of kms.Encryptor method
func (k *KeyManager) Decrypt(ctx context.Context, keyID []byte, blob []byte, context []byte) ([]byte, error) {
	var encryptionContext map[string]string
	if context != nil {
		//  set encryption context in case of provided additional authenticated data
		encryptionContext = map[string]string{"context": string(context)}
	}

	return k.client.Decrypt(ctx, getAliasedName(string(keyID)), blob, encryptionContext)
}

func getAliasedName(name string) string {
	return "alias/" + name
}
