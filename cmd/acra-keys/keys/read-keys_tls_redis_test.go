//go:build integration && redis && tls
// +build integration,redis,tls

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
	"crypto/tls"
	"encoding/base64"
	"flag"
	"github.com/cossacklabs/acra/keystore/keyloader/env_loader"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/utils/tests"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/keyloader"
)

func newClientTLSConfig(t *testing.T) *tls.Config {
	verifier := network.NewCertVerifierAll()
	workingDirectory := tests.GetSourceRootDirectory(t)
	clientConfig, err := network.NewTLSConfig("localhost", filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"), filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.key"), filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.crt"), 4, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return clientConfig
}

func prepareTLSRedisConfigForFlagSet(flagset *flag.FlagSet, t *testing.T) *cmd.RedisOptions {
	// registering flags overrides values with default
	// here we load values from env variables and use them for tests
	tempOptions := cmd.GetTestRedisOptions(t)
	workingDirectory := tests.GetSourceRootDirectory(t)
	if err := flagset.Lookup("redis_tls_client_ca").Value.Set(filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt")); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_cert").Value.Set(filepath.Join(workingDirectory, "tests/ssl/acra-client/acra-client.crt")); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_key").Value.Set(filepath.Join(workingDirectory, "tests/ssl/acra-client/acra-client.key")); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_client_auth").Value.Set(strconv.FormatUint(uint64(tls.RequireAndVerifyClientCert), 10)); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_ocsp_client_from_cert").Value.Set("ignore"); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_crl_client_from_cert").Value.Set("ignore"); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_host_port").Value.Set(tempOptions.HostPort); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_password").Value.Set(tempOptions.Password); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_db_keys").Value.Set(strconv.FormatUint(uint64(tempOptions.DBKeys), 10)); err != nil {
		t.Fatal(err)
	}
	if err := flagset.Lookup("redis_tls_enable").Value.Set("true"); err != nil {
		t.Fatal(err)
	}
	options := cmd.ParseRedisCLIParametersFromFlags(flagset, "")
	return options
}

func TestReadCMD_TLSRedis_V2(t *testing.T) {
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

	options := prepareTLSRedisConfigForFlagSet(flagSet, t)
	// remove all generated keys at the end
	client, err := storage.NewRedisClient(options.HostPort, options.Password, options.DBKeys, newClientTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer client.FlushAll()

	setFlags := map[string]string{
		"keystore_encryption_type": keyloader.KeystoreStrategyEnvMasterKey,
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

func TestReadCMD_TLSRedis_V1(t *testing.T) {
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

	options := prepareTLSRedisConfigForFlagSet(flagSet, t)
	// remove all generated keys at the end
	client, err := storage.NewRedisClient(options.HostPort, options.Password, options.DBKeys, newClientTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer client.FlushAll()

	setFlags := map[string]string{
		"keystore_encryption_type": keyloader.KeystoreStrategyEnvMasterKey,
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
