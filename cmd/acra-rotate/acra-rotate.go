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
	"path/filepath"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
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

func openKeyStoreV1(dirPath string) keystore.RotateStorageKeyStore {
	absKeysDir, err := filepath.Abs(dirPath)
	if err != nil {
		log.WithError(err).Errorln("Can't get absolute path for keys_dir")
		os.Exit(1)
	}
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Can't load master key")
		os.Exit(1)
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		os.Exit(1)
	}
	keystorage, err := filesystem.NewFilesystemKeyStore(absKeysDir, scellEncryptor)
	if err != nil {
		log.WithError(err).Errorln("can't initialize key store")
		os.Exit(1)
	}
	return keystorage
}

func openKeyStoreV2(keyDirPath string) keystore.RotateStorageKeyStore {
	encryption, signature, err := keystoreV2.GetMasterKeysFromEnvironment()
	if err != nil {
		log.WithError(err).Error("cannot read master keys from environment")
		os.Exit(1)
	}
	suite, err := keystoreV2.NewSCellSuite(encryption, signature)
	if err != nil {
		log.WithError(err).Error("failed to initialize Secure Cell crypto suite")
		os.Exit(1)
	}
	keyDir, err := filesystemV2.OpenDirectoryRW(keyDirPath, suite)
	if err != nil {
		log.WithError(err).WithField("path", keyDirPath).Error("cannot open key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDir)
}

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which the keys will be loaded")
	keystoreOpts := flag.String("keystore", "", "force Key Store format: v1 (current), v2 (experimental)")
	fileMapConfig := flag.String("file_map_config", "", "Path to file with map of <ZoneId>: <FilePaths> in json format {\"zone_id1\": [\"filepath1\", \"filepath2\"], \"zone_id2\": [\"filepath1\", \"filepath2\"]}")

	sqlSelect := flag.String("sql_select", "", "Select query with ? as placeholders where last columns in result must be ClientId/ZoneId and AcraStruct. Other columns will be passed into insert/update query into placeholders")
	sqlUpdate := flag.String("sql_update", "", "Insert/Update query with ? as placeholder where into first will be placed rotated AcraStruct")
	connectionString := flag.String("db_connection_string", "", "Connection string to db")
	useMysql := flag.Bool("mysql_enable", false, "Handle MySQL connections")
	zoneMode := flag.Bool("zonemode_enable", true, "Rotate acrastructs as it was encrypted with zonemode or without. With zonemode_enable=true will be used zoneID for encryption/decryption. If false then key id will not be used")
	_ = flag.Bool("postgresql_enable", false, "Handle Postgresql connections")
	dryRun := flag.Bool("dry-run", false, "perform rotation without saving rotated AcraStructs and keys")
	logging.SetLogLevel(logging.LogVerbose)

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	var keystorage keystore.RotateStorageKeyStore
	if *keystoreOpts == "" {
		if filesystemV2.IsKeyDirectory(*keysDir) {
			*keystoreOpts = "v2"
		} else {
			*keystoreOpts = "v1"
		}
	}
	switch *keystoreOpts {
	case "v1":
		keystorage = openKeyStoreV1(*keysDir)
	case "v2":
		keystorage = openKeyStoreV2(*keysDir)
	default:
		log.Errorf("unknown keystore option: %v", *keystoreOpts)
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
