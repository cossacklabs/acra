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
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

// Constants used by AcraRotate
var (
	// DefaultConfigPath relative path to config which will be parsed as default
	DefaultConfigPath = utils.GetConfigPathByName("acra-rotate")
	ServiceName       = "acra-rotate"
)

func initKeyStore(dirPath string) (keystore.KeyStore, error) {
	absKeysDir, err := filepath.Abs(dirPath)
	if err != nil {
		log.WithError(err).Errorln("Can't get absolute path for keys_dir")
		os.Exit(1)
	}
	masterKey, err := keystore.GetMasterKeyFromEnvironment()
	if err != nil {
		log.WithError(err).Errorln("Can't load master key")
		return nil, err
	}
	scellEncryptor, err := keystore.NewSCellKeyEncryptor(masterKey)
	if err != nil {
		log.WithError(err).Errorln("Can't init scell encryptor")
		return nil, err
	}
	keystorage, err := filesystem.NewFilesystemKeyStore(absKeysDir, scellEncryptor)
	if err != nil {
		log.WithError(err).Errorln("Can't create key store")
		return nil, err
	}
	return keystorage, nil
}

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which the keys will be loaded")
	fileMapConfig := flag.String("file_map_config", "", "Path to file with map of <ZoneId>: <FilePaths> in json format {\"zone_id1\": [\"filepath1\", \"filepath2\"], \"zone_id2\": [\"filepath1\", \"filepath2\"]}")

	sqlSelect := flag.String("sql_select", "", "Select query with ? as placeholders where last columns in result must be ClientId/ZoneId and AcraStruct. Other columns will be passed into insert/update query into placeholders")
	sqlUpdate := flag.String("sql_update", "", "Insert/Update query with ? as placeholder where into first will be placed rotated AcraStruct")
	connectionString := flag.String("db_connection_string", "", "Connection string to db")
	useMysql := flag.Bool("mysql_enable", false, "Handle MySQL connections")
	_ = flag.Bool("postgresql_enable", false, "Handle Postgresql connections")
	dryRun := flag.Bool("dry-run", false, "perform rotation without saving rotated AcraStructs and keys")
	logging.SetLogLevel(logging.LogVerbose)

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	keystorage, err := initKeyStore(*keysDir)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize keystore")
		os.Exit(1)
	}
	if *dryRun {
		log.Infoln("Rotating in dry-run mode")
	}
	if *fileMapConfig != "" {
		runFileRotation(*fileMapConfig, keystorage, *dryRun)
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
		if !rotateDb(*sqlSelect, *sqlUpdate, db, keystorage, encoder, *dryRun) {
			os.Exit(1)
		}
	}
}
