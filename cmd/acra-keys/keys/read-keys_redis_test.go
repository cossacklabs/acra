//go:build integration && redis && !tls
// +build integration,redis,!tls

/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keys

import (
	"encoding/base64"
	"flag"
	"io"
	"strconv"
	"testing"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	storage2 "github.com/cossacklabs/acra/pseudonymization/storage"
)

func TestReadCMD_Redis_V2(t *testing.T) {
	testOptions := cmd.GetTestRedisOptions(t)
	client, err := storage2.NewRedisClient(testOptions.HostPort, testOptions.Password, testOptions.DBKeys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.FlushAll()

	clientID := []byte("testclientid")
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystoreV2.NewSerializedMasterKeys()
	if err != nil {
		t.Fatal(err)
	}

	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")
	cmd.RegisterRedisKeystoreParametersWithPrefix(flagSet, "", "")

	setFlags := map[string]string{
		"keystore_encryption_type": keyloader.KeystoreStrategyEnvMasterKey,
		"redis_host_port":          testOptions.HostPort,
		"redis_password":           testOptions.Password,
		"redis_db_keys":            strconv.FormatUint(uint64(testOptions.DBKeys), 10),
	}

	for flag, value := range setFlags {
		err = flagSet.Set(flag, value)
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	extractor := args.NewServiceExtractor(flagSet, map[string]interface{}{})

	t.Run("read storage-public key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			contextID:   clientID,
			readKeyKind: keystore.KeyStoragePublic,
			FlagSet:     flagSet,
			outWriter:   io.Discard,
			extractor:   extractor,
		}

		store, err := openKeyStoreV2(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})

	t.Run("read symmetric-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			FlagSet:     flagSet,
			contextID:   clientID,
			readKeyKind: keystore.KeySymmetric,
			outWriter:   io.Discard,
			extractor:   extractor,
		}

		store, err := openKeyStoreV2(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})
}

func TestReadCMD_Redis_V1(t *testing.T) {
	testOptions := cmd.GetTestRedisOptions(t)
	client, err := storage2.NewRedisClient(testOptions.HostPort, testOptions.Password, testOptions.DBKeys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.FlushAll()

	clientID := []byte("testclientid")
	keyloader.RegisterKeyEncryptorFabric(keyloader.KeystoreStrategyEnvMasterKey, env_loader.NewEnvKeyEncryptorFabric(keystore.AcraMasterKeyVarName))

	masterKey, err := keystore.GenerateSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}

	flagSet := flag.NewFlagSet(CmdMigrateKeys, flag.ContinueOnError)
	keyloader.RegisterCLIParametersWithFlagSet(flagSet, "", "")

	cmd.RegisterRedisKeystoreParametersWithPrefix(flagSet, "", "")

	setFlags := map[string]string{
		"keystore_encryption_type": keyloader.KeystoreStrategyEnvMasterKey,
		"redis_host_port":          testOptions.HostPort,
		"redis_password":           testOptions.Password,
		"redis_db_keys":            strconv.FormatUint(uint64(testOptions.DBKeys), 10),
	}

	for flag, value := range setFlags {
		err = flagSet.Set(flag, value)
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	extractor := args.NewServiceExtractor(flagSet, map[string]interface{}{})

	dirName := t.TempDir()

	t.Run("read storage-public key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			FlagSet:     flagSet,
			contextID:   clientID,
			readKeyKind: keystore.KeyStoragePublic,
			outWriter:   io.Discard,
			extractor:   extractor,
		}

		store, err := openKeyStoreV1(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateDataEncryptionKeys(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})

	t.Run("read symmetric-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			FlagSet:     flagSet,
			contextID:   clientID,
			readKeyKind: keystore.KeySymmetric,
			outWriter:   io.Discard,
			extractor:   extractor,
		}

		store, err := openKeyStoreV1(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateClientIDSymmetricKey(clientID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})
}
