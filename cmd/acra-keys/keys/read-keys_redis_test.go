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
	storage2 "github.com/cossacklabs/acra/pseudonymization/storage"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
)

func TestReadCMD_Redis_V2(t *testing.T) {
	testOptions := cmd.GetTestRedisOptions(t)
	client, err := storage2.NewRedisClient(testOptions.HostPort, testOptions.Password, testOptions.DBKeys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.FlushAll()

	zoneID := []byte("DDDDDDDDHCzqZAZNbBvybWLR")
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

	os.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	t.Run("read storage-public key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			contextID:   clientID,
			readKeyKind: KeyStoragePublic,
			FlagSet:     flagSet,
			outWriter:   io.Discard,
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
			readKeyKind: KeySymmetric,
			outWriter:   io.Discard,
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

	t.Run("read symmetric-zone-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			FlagSet:     flagSet,
			contextID:   zoneID,
			readKeyKind: KeyZoneSymmetric,
			outWriter:   io.Discard,
		}

		store, err := openKeyStoreV2(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateZoneIDSymmetricKey(zoneID)
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

	zoneID := []byte("DDDDDDDDHCzqZAZNbBvybWLR")
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

	os.Setenv(keystore.AcraMasterKeyVarName, base64.StdEncoding.EncodeToString(masterKey))

	dirName, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dirName)

	t.Run("read storage-public key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			FlagSet:     flagSet,
			contextID:   clientID,
			readKeyKind: KeyStoragePublic,
			outWriter:   io.Discard,
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
			readKeyKind: KeySymmetric,
			outWriter:   io.Discard,
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

	t.Run("read symmetric-zone-key", func(t *testing.T) {
		readCmd := &ReadKeySubcommand{
			CommonKeyStoreParameters: CommonKeyStoreParameters{
				keyDir: dirName,
			},
			FlagSet:     flagSet,
			contextID:   zoneID,
			readKeyKind: KeyZoneSymmetric,
			outWriter:   io.Discard,
		}

		store, err := openKeyStoreV1(readCmd)
		if err != nil {
			t.Fatal(err)
		}

		err = store.GenerateZoneIDSymmetricKey(zoneID)
		if err != nil {
			t.Fatal(err)
		}

		readCmd.Execute()
	})
}
