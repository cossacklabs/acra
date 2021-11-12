//go:build integration && vault
// +build integration,vault

package hashicorp

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cossacklabs/acra/keystore/v2/keystore"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

type (
	tearDownState func(t *testing.T)

	testVaultManager struct {
		client *api.Client
	}
)

const (
	AllowSleepCounts = 30
	EnvTestVaultPort = "TEST_VAULT_PORT"
	EnvTestVaultHost = "TEST_VAULT_HOST"
)

const (
	VaultDefaultPort     = "8200"
	VaultDefaultHost     = "localhost"
	ReadFailSleepTimeout = 100
)

func newTestVaultManager(t *testing.T) testVaultManager {
	t.Helper()

	config := api.DefaultConfig()
	port, ok := os.LookupEnv(EnvTestVaultPort)
	if !ok {
		port = VaultDefaultPort
	}
	host, ok := os.LookupEnv(EnvTestVaultHost)
	if !ok {
		host = VaultDefaultHost
	}
	config.Address = fmt.Sprintf("https://%s:%s", host, port)
	if err := config.ConfigureTLS(&api.TLSConfig{Insecure: true}); err != nil {
		t.Fatal(err)
	}
	config.Timeout = time.Millisecond * 500
	client, err := api.NewClient(config)
	if err != nil {
		t.Fatalf("Failed to initialize Vault client: %v", err)
	}
	client.SetToken("root_token")

	return testVaultManager{
		client: client,
	}
}

func (vaultManager testVaultManager) mountKVEngine(path, version string) (tearDownState, error) {
	err := vaultManager.client.Sys().Mount(path, &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": version,
		},
	})
	if err != nil {
		return nil, err
	}

	var sleepCounts int
	// need to wait until proper mounting of the provided path
	for {
		_, err := vaultManager.client.Logical().Read(path)
		if err == nil {
			break
		}

		if sleepCounts == AllowSleepCounts {
			return nil, fmt.Errorf("to many sleep counts - max value reached %d", AllowSleepCounts)
		}

		time.Sleep(time.Millisecond * ReadFailSleepTimeout)
		sleepCounts++
	}
	return func(t *testing.T) {
		if err := vaultManager.client.Sys().Unmount(path); err != nil {
			t.Fatal(err)
		}
	}, nil
}

func (vaultManager testVaultManager) putSecretByPath(path, keyID string, value interface{}) (tearDownState, error) {
	payload := map[string]interface{}{}

	if strings.Contains(path, dataSecretPathPart) {
		payload[dataSecretPathPart] = map[string]interface{}{
			keyID: value,
		}
	} else {
		payload[keyID] = value
	}

	_, err := vaultManager.client.Logical().Write(path, payload)
	if err != nil {
		return nil, err
	}
	return func(t *testing.T) {
		if _, err := vaultManager.client.Logical().Delete(path); err != nil {
			t.Fatal(err)
		}
	}, nil
}

func TestVaultLoaderV1Engine(t *testing.T) {
	vaultManager := newTestVaultManager(t)

	vaultLoader := VaultLoader{
		client: vaultManager.client,
	}

	path := "kv_path_v1/"
	tearDownMount, err := vaultManager.mountKVEngine(path, kvSecretEngineVersion1)
	if err != nil {
		t.Fatal(err)
	}
	defer tearDownMount(t)

	t.Run("Successfully get secret engine", func(t *testing.T) {
		vaultLoader.secretPath = path

		engine, err := vaultLoader.getKVEngine()
		assert.NoError(t, err)
		assert.Equal(t, kvSecretEngineType, engine.secretType)
		assert.Equal(t, kvSecretEngineVersion1, engine.version)
		assert.Contains(t, engine.path, path)
	})

	t.Run("masterKeySecretID not found error (version 1)", func(t *testing.T) {
		writePath := filepath.Join(path, "test")

		tearDownPut, err := vaultManager.putSecretByPath(writePath, "invalid_key_id", "value")
		if err != nil {
			t.Fatal(err)
		}
		defer tearDownPut(t)

		vaultLoader.secretPath = writePath

		key, err := vaultLoader.getSecretKey()
		assert.Equal(t, ErrMasterKeyNotFound, err)
		assert.Equal(t, "", key)
	})

	t.Run("getSecretKey() success", func(t *testing.T) {
		writePath := filepath.Join(path, "key")

		masterKey := "master_key_value"
		tearDownPut, err := vaultManager.putSecretByPath(writePath, masterKeySecretID, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		defer tearDownPut(t)

		vaultLoader.secretPath = writePath

		key, err := vaultLoader.getSecretKey()
		assert.NoError(t, err)
		assert.Equal(t, masterKey, key)
	})
}

func TestVaultLoaderV2Engine(t *testing.T) {
	vaultManager := newTestVaultManager(t)

	vaultLoader := VaultLoader{
		client: vaultManager.client,
	}

	var expectedNil *keystore.SerializedKeys

	path := "kv_path_v2/"
	tearDown, err := vaultManager.mountKVEngine(path, kvSecretEngineVersion2)
	if err != nil {
		t.Fatal(err)
	}
	defer tearDown(t)

	t.Run("Successfully get secret engine", func(t *testing.T) {
		vaultLoader.secretPath = path

		engine, err := vaultLoader.getKVEngine()
		assert.NoError(t, err)
		assert.Equal(t, kvSecretEngineType, engine.secretType)
		assert.Equal(t, kvSecretEngineVersion2, engine.version)
		assert.Contains(t, engine.path, path)
	})

	t.Run("Search unmount path error", func(t *testing.T) {
		vaultLoader.secretPath = "test_path"

		engine, err := vaultLoader.getKVEngine()
		assert.Equal(t, ErrEngineNotFound, err)
		assert.Equal(t, engine, secretEngine{})
	})

	t.Run("getKVEngine() error", func(t *testing.T) {
		vaultLoader.secretPath = "test_path"

		key, err := vaultLoader.getSecretKey()
		assert.Equal(t, ErrEngineNotFound, err)
		assert.Equal(t, "", key)
	})

	t.Run("No key found error", func(t *testing.T) {
		vaultLoader.secretPath = "kv_path_v2/foo"

		key, err := vaultLoader.getSecretKey()
		assert.Equal(t, ErrSecretNotFound, err)
		assert.Equal(t, "", key)
	})

	t.Run("masterKeySecretID not found error (version 2)", func(t *testing.T) {
		writePath := filepath.Join(path, "data", "key")
		secretPath := filepath.Join(path, "key")

		tearDownPut, err := vaultManager.putSecretByPath(writePath, "invalid_key_id", "value")
		if err != nil {
			t.Fatal(err)
		}
		defer tearDownPut(t)

		vaultLoader.secretPath = secretPath

		key, err := vaultLoader.getSecretKey()
		assert.Equal(t, ErrMasterKeyNotFound, err)
		assert.Equal(t, "", key)
	})

	t.Run("convert ACRA_MASTER_KEY to string error", func(t *testing.T) {
		writePath := filepath.Join(path, "data", "key")
		secretPath := filepath.Join(path, "key")

		tearDownPut, err := vaultManager.putSecretByPath(writePath, masterKeySecretID, 444)
		if err != nil {
			t.Fatal(err)
		}
		defer tearDownPut(t)

		vaultLoader.secretPath = secretPath

		key, err := vaultLoader.getSecretKey()
		assert.Equal(t, ErrMasterKeyConvert, err)
		assert.Equal(t, "", key)
	})

	t.Run("getSecretKey() success (version 2)", func(t *testing.T) {
		writePath := filepath.Join(path, "data", "key")
		secretPath := filepath.Join(path, "key")

		masterKey := "master_key_value"
		tearDownPut, err := vaultManager.putSecretByPath(writePath, masterKeySecretID, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		defer tearDownPut(t)

		vaultLoader.secretPath = secretPath

		key, err := vaultLoader.getSecretKey()
		assert.NoError(t, err)
		assert.Equal(t, masterKey, key)
	})

	t.Run("base64 decode error", func(t *testing.T) {
		writePath := filepath.Join(path, "data", "foo")

		masterKey := "master_key_value"
		tearDownPut, err := vaultManager.putSecretByPath(writePath, masterKeySecretID, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		defer tearDownPut(t)

		vaultLoader.secretPath = "kv_path_v2/foo"

		keys, err := vaultLoader.getSecretKeys()
		assert.Equal(t, base64.CorruptInputError(6), err)
		assert.Equal(t, expectedNil, keys)
	})

	t.Run("deserialize to SerializedKeys error", func(t *testing.T) {

		writePath := filepath.Join(path, "data", "foo")

		masterKey := base64.StdEncoding.EncodeToString([]byte("master_key_value"))
		tearDownPut, err := vaultManager.putSecretByPath(writePath, masterKeySecretID, masterKey)
		if err != nil {
			t.Fatal(err)
		}
		defer tearDownPut(t)

		vaultLoader.secretPath = "kv_path_v2/foo"

		keys, err := vaultLoader.getSecretKeys()
		assert.Error(t, err)
		assert.Equal(t, expectedNil, keys)
	})
}
