package hashicorp

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	keystoreCE "github.com/cossacklabs/acra/keystore"
	keystoreV2CE "github.com/cossacklabs/acra/keystore/v2/keystore"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

const vaultAPIToken = "VAULT_API_TOKEN"

const (
	kvSecretEngineVersion2 = "2"
	kvSecretEngineVersion1 = "1"
	kvSecretEngineType     = "kv"
	dataSecretPathPart     = "data"

	masterKeySecretID      = "acra_master_key"
	vaultMountListEndpoint = "/sys/internal/ui/mounts"
)

// set of predefined errors used in HashiCorp Vault loader and its tests
var (
	ErrEngineNotFound     = errors.New("unable to find secret engine")
	ErrEmptyAPIToken      = errors.New("HashiCorp Vault api token is empty")
	ErrSecretNotFound     = errors.New("HashiCorp Vault kv secret not found")
	ErrDataPathNotFound   = errors.New("no data path found for kv secret engine version 2")
	ErrMasterKeyNotFound  = errors.New("ACRA_MASTER_KEY was not found by kv secret path")
	ErrMasterKeyConvert   = errors.New("unable to convert acra master key id to string")
	ErrNoOptionsFound     = errors.New("no options found for secret engine path")
	ErrNoKVSecretEngine   = errors.New("incorrect secret engine type - should be kv")
	ErrGetEngineInfo      = errors.New("failed to get secret engine info by path")
	ErrGetEngineType      = errors.New("failed to get secret engine type by path")
	ErrParseEngineType    = errors.New("failed to parse secret engine type by path")
	ErrParseEngineOptions = errors.New("failed to parse secret engine options")
	ErrGetEngineVersion   = errors.New("failed to get secret engine version")
	ErrConvertToPathList  = errors.New("failed to convert secrets to kv secrets list")
)

// VaultLoader is HashiCorp Vault ACRA_MASTER_KEY loader implementation, it consist of api.Client used for interacting
// with HashiCorp Vault throughout API and secretPath which is the path where VaultLoader should look up for ACRA_MASTER_KEY;
// where secretPath is user provided value.
type (
	secretEngine struct {
		path       string
		version    string
		secretType string
	}

	VaultLoader struct {
		client     *api.Client
		secretPath string
	}
)

// NewVaultLoader read VAULT_API_TOKEN env, decode it and return initialized VaultLoader
func NewVaultLoader(config *api.Config, secretPath string) (*VaultLoader, error) {
	b64value := os.Getenv(vaultAPIToken)
	if len(b64value) == 0 {
		log.Warnf("%v environment variable is not set", vaultAPIToken)
		return nil, ErrEmptyAPIToken
	}

	decodeValue, err := base64.StdEncoding.DecodeString(b64value)
	if err != nil {
		log.WithError(err).Warnf("Failed to decode %s", vaultAPIToken)
		return nil, err
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	vaultToken := strings.Trim(string(decodeValue), "\n")
	client.SetToken(vaultToken)
	return &VaultLoader{
		client:     client,
		secretPath: secretPath,
	}, nil
}

// LoadMasterKey read ACRA_MASTER_KEY key from HashiCorp Vault by secretPath, decode and validate it.
func (loader VaultLoader) LoadMasterKey() ([]byte, error) {
	b64value, err := loader.getSecretKey()
	if err != nil {
		log.WithError(err).Warnf("Failed to get secret key by path %s", loader.secretPath)
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(b64value)
	if err != nil {
		log.WithError(err).Warnf("Failed to decode %s", masterKeySecretID)
		return nil, err
	}
	if err := keystoreCE.ValidateMasterKey(key); err != nil {
		log.WithError(err).Warnf("Failed to validate %s", masterKeySecretID)
		return nil, err
	}

	return key, nil
}

// LoadMasterKeys read ACRA_MASTER_KEYs from HashiCorp Vault and validate it.
func (loader VaultLoader) LoadMasterKeys() ([]byte, []byte, error) {
	keys, err := loader.getSecretKeys()
	if err != nil {
		log.WithError(err).Warnf("Failed to get secret keys by path %s", loader.secretPath)
		return nil, nil, err
	}

	if subtle.ConstantTimeCompare(keys.Encryption, keys.Signature) == 1 {
		log.Warnf("%s: ACRA_MASTER_KEYs must not be the same", masterKeySecretID)
		return nil, nil, keystoreV2CE.ErrEqualMasterKeys
	}

	err = keystoreCE.ValidateMasterKey(keys.Encryption)
	if err != nil {
		log.WithError(err).Warnf("%s: invalid encryption key", masterKeySecretID)
		return nil, nil, err
	}
	err = keystoreCE.ValidateMasterKey(keys.Signature)
	if err != nil {
		log.WithError(err).Warnf("%s: invalid signature key", masterKeySecretID)
		return nil, nil, err
	}

	return keys.Encryption, keys.Signature, nil
}

// getSecretKeys read ACRA_MASTER_KEY base64 value, decode it and deserialize into keystoreV2CE.SerializedKeys.
func (loader VaultLoader) getSecretKeys() (*keystoreV2CE.SerializedKeys, error) {
	b64value, err := loader.getSecretKey()
	if err != nil {
		log.WithError(err).Warnf("Failed to get secret by path %s", loader.secretPath)
		return nil, err
	}

	keyData, err := base64.StdEncoding.DecodeString(b64value)
	if err != nil {
		log.WithError(err).Warnf("Failed to decode %s", masterKeySecretID)
		return nil, err
	}

	keys := &keystoreV2CE.SerializedKeys{}
	err = keys.Unmarshal(keyData)
	if err != nil {
		log.WithError(err).Warnf("Failed to parse %s", masterKeySecretID)
		return nil, err
	}
	return keys, nil
}

// getSecretKey defines the version of the kv secret engine provided by the user and read secret by appropriate path.
func (loader VaultLoader) getSecretKey() (key string, err error) {
	engine, err := loader.getKVEngine()
	if err != nil {
		log.WithError(err).Warn("Unable to get KV secret engine")
		return
	}

	readPath := loader.secretPath

	if engine.version == kvSecretEngineVersion2 {
		splits := strings.Split(loader.secretPath, "/")
		if len(splits) < 2 {
			return "", errors.New("unable to split secret path")
		}
		dstPath := append([]string{engine.path, dataSecretPathPart}, splits[1:]...)

		readPath = filepath.Join(dstPath...)
	}

	secret, err := loader.client.Logical().Read(readPath)
	if err != nil {
		return
	}

	if secret == nil {
		return "", ErrSecretNotFound
	}

	lookupPath := secret.Data
	if engine.version == kvSecretEngineVersion2 {
		dataPath, ok := secret.Data[dataSecretPathPart].(map[string]interface{}) // for version 2 we should look up for data secret path
		if !ok {
			return "", ErrDataPathNotFound
		}
		lookupPath = dataPath
	}

	rawMasterKey, ok := lookupPath[masterKeySecretID]
	if !ok {
		return "", ErrMasterKeyNotFound
	}

	masterKey, ok := rawMasterKey.(string)
	if !ok {
		return "", ErrMasterKeyConvert
	}

	return masterKey, nil
}

// getKVEngine read info about all secret engines to get kv engine version provided by user.
// should read it to construct correct lookup path for the ACRA_MASTER_KEY search.
func (loader VaultLoader) getKVEngine() (engine secretEngine, err error) {
	secret, err := loader.client.Logical().Read(vaultMountListEndpoint)
	if err != nil {
		return
	}

	secrets, ok := secret.Data["secret"]
	if !ok {
		return secretEngine{}, ErrEngineNotFound
	}

	paths, ok := secrets.(map[string]interface{})
	if !ok {
		return secretEngine{}, ErrConvertToPathList
	}

	pathSplits := strings.Split(loader.secretPath, string(os.PathSeparator))
	for pathName := range paths {
		if pathSplits[0] != strings.Trim(pathName, "/") {
			continue
		}

		pathInfo, ok := paths[pathName].(map[string]interface{})
		if !ok {
			return secretEngine{}, ErrGetEngineInfo
		}

		return getEngineByPath(pathName, pathInfo)
	}

	return secretEngine{}, ErrEngineNotFound
}

// getEngineByPath extract info about secret engine by secret path provided by user
func getEngineByPath(path string, pathInfo map[string]interface{}) (secretEngine, error) {
	rawType, ok := pathInfo["type"]
	if !ok {
		return secretEngine{}, ErrGetEngineType
	}

	secretType, ok := rawType.(string)
	if !ok {
		return secretEngine{}, ErrParseEngineType
	}

	if secretType != kvSecretEngineType {
		return secretEngine{}, ErrNoKVSecretEngine
	}

	rawOptions, ok := pathInfo["options"]
	if !ok {
		return secretEngine{}, ErrNoOptionsFound
	}

	engine := secretEngine{
		path:       path,
		secretType: secretType,
		version:    kvSecretEngineVersion1,
	}

	// if we could not parse an option, consider 1 default version of secret engine
	options, ok := rawOptions.(map[string]interface{})
	if !ok {
		return engine, nil
	}

	version, ok := options["version"].(string)
	if !ok {
		return secretEngine{}, ErrGetEngineVersion
	}

	engine.version = version
	return engine, nil
}
