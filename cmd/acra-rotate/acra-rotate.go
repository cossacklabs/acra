/*
Copyright 2018, Cossack Labs Limited

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

// Package main is entry point for acra-rotate. Acra-rotate provide console utility to rotate private/zone keys and re-encrypt
// data stored in database or as files
package main

import (
	"database/sql"
	"flag"
	"os"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	"github.com/cossacklabs/acra/keystore/keyloader/hashicorp"
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"

	log "github.com/sirupsen/logrus"
)

// Constants used by AcraRotate
var (
	// DefaultConfigPath relative path to config which will be parsed as default
	DefaultConfigPath = utils.GetConfigPathByName("acra-rotate")
	ServiceName       = "acra-rotate"
)

func openKeyStoreV1(dirPath string, loader keyloader.MasterKeyLoader) keystore.ServerKeyStore {
	masterKey, err := loader.LoadMasterKey()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		os.Exit(1)
	}

	keyStore := filesystem.NewCustomFilesystemKeyStore()
	keyStore.KeyDirectory(dirPath)
	keyStore.Encryptor(scellEncryptor)
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		keyStorage, err := filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, nil)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't initialize Redis client")
			os.Exit(1)
		}
		keyStore.Storage(keyStorage)
	}
	keyStoreV1, err := keyStore.Build()
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore")
		os.Exit(1)
	}
	return keyStoreV1
}

func openKeyStoreV2(keyDirPath string, loader keyloader.MasterKeyLoader) keystore.ServerKeyStore {
	encryption, signature, err := loader.LoadMasterKeys()
	if err != nil {
		log.WithError(err).Errorln("Cannot load master key")
		os.Exit(1)
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("failed to initialize Secure Cell crypto suite")
		os.Exit(1)
	}
	var backend filesystemBackendV2.Backend
	redis := cmd.GetRedisParameters()
	if redis.KeysConfigured() {
		config := &filesystemBackendV2.RedisConfig{
			RootDir: keyDirPath,
			Options: redis.KeysOptions(),
		}
		backend, err = filesystemBackendV2.OpenRedisBackend(config)
		if err != nil {
			log.WithError(err).Error("Cannot connect to Redis keystore")
			os.Exit(1)
		}
	} else {
		backend, err = filesystemBackendV2.OpenDirectoryBackend(keyDirPath)
		if err != nil {
			log.WithError(err).Error("Cannot open key directory")
			os.Exit(1)
		}
	}
	keyDirectory, err := filesystemV2.CustomKeyStore(backend, suite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDirectory)
}

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which the keys will be loaded")
	fileMapConfig := flag.String("file_map_config", "", "Path to file with map of <ZoneId>: <FilePaths> in json format {\"zone_id1\": [\"filepath1\", \"filepath2\"], \"zone_id2\": [\"filepath1\", \"filepath2\"]}")
	cmd.RegisterRedisKeyStoreParameters()

	sqlSelect := flag.String("sql_select", "", "Select query with ? as placeholders where last columns in result must be ClientId/ZoneId and AcraStruct. Other columns will be passed into insert/update query into placeholders")
	sqlUpdate := flag.String("sql_update", "", "Insert/Update query with ? as placeholder where into first will be placed rotated AcraStruct")
	connectionString := flag.String("db_connection_string", "", "Connection string to db")
	useMysql := flag.Bool("mysql_enable", false, "Handle MySQL connections")
	zoneMode := flag.Bool("zonemode_enable", true, "Rotate acrastructs as it was encrypted with zonemode or without. With zonemode_enable=true will be used zoneID for encryption/decryption. If false then key id will not be used")
	_ = flag.Bool("postgresql_enable", false, "Handle Postgresql connections")
	dryRun := flag.Bool("dry-run", false, "perform rotation without saving rotated AcraStructs and keys")
	logging.SetLogLevel(logging.LogVerbose)

	kms.RegisterCLIParameters()
	hashicorp.RegisterVaultCLIParameters()

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	keyLoader, err := keyloader.GetInitializedMasterKeyLoader(hashicorp.GetVaultCLIParameters(), kms.GetCLIParameters())
	if err != nil {
		log.WithError(err).Errorln("Can't initialize ACRA_MASTER_KEY loader")
		os.Exit(1)
	}

	var keystorage keystore.ServerKeyStore
	if filesystemV2.IsKeyDirectory(*keysDir) {
		keystorage = openKeyStoreV2(*keysDir, keyLoader)
	} else {
		keystorage = openKeyStoreV1(*keysDir, keyLoader)
	}
	if err := crypto.InitRegistry(keystorage); err != nil {
		log.WithError(err).Errorln("Can't initialize crypto registry")
		os.Exit(1)
	}
	if *dryRun {
		log.Infoln("Rotating in dry-run mode")
	}
	if *fileMapConfig != "" {
		runFileRotation(*fileMapConfig, keystorage, *zoneMode, *dryRun)
	}
	if *sqlSelect != "" || *sqlUpdate != "" {
		if *sqlSelect == "" || *sqlUpdate == "" {
			log.Errorln("sql_select and sql_update must be set both")
			os.Exit(1)
		}
		var db *sql.DB
		var encoder utils.BinaryEncoder
		if *useMysql {
			db, err = sql.Open("mysql", *connectionString)
			encoder = &utils.HexEncoder{}
		} else {
			db, err = sql.Open("postgres", *connectionString)

			encoder = &utils.MysqlEncoder{}
		}

		if err != nil {
			log.WithError(err).Errorln("Can't connect to db")
			os.Exit(1)
		}
		if db == nil {
			log.Errorln("Can't initialize db driver")
			os.Exit(1)
		}
		if err := db.Ping(); err != nil {
			log.WithError(err).Errorln("Error on pinging database", *connectionString)
			os.Exit(1)
		}
		log.WithFields(log.Fields{"select_query": *sqlSelect, "update_query": *sqlUpdate}).Infoln("Rotate data in database")
		if !rotateDb(*sqlSelect, *sqlUpdate, db, keystorage, encoder, *zoneMode, *dryRun) {
			os.Exit(1)
		}
	}
}
