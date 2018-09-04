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
	usePostgresql := flag.Bool("postgresql_enable", false, "Handle Postgresql connections")
	// --sql_select=select id, zone_id, data from test_example_with_zone;
	// --sql_update="update test set data=? where id=?;"
	// --db_connection_string="postgres://test:test@127.0.0.1:5432/test"
	// --db_connection_string="postgres://test:test@127.0.0.1:5432/test" --sql_update="update test_example_with_zone set data=? where id=?;" --sql_select=select id, zone_id, data from test_example_with_zone;
	logging.SetLogLevel(logging.LogVerbose)

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).Errorln("Can't parse args")
		os.Exit(1)
	}

	keystorage, err := initKeyStore(*keysDir)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize keystore")
		os.Exit(1)
	}
	if *fileMapConfig != "" {
		runFileRotation(*fileMapConfig, keystorage)
	}
	if *sqlSelect != "" || *sqlUpdate != "" {
		if *sqlSelect == "" || *sqlUpdate == "" {
			log.Errorln("sql_select and sql_update must be set both")
			os.Exit(1)
		}
		var db *sql.DB
		if *usePostgresql {
			db, err = sql.Open("postgres", *connectionString)
		} else if *useMysql {
			db, err = sql.Open("mysql", *connectionString)
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
			log.WithError(err).Errorln("Error on database ping", *connectionString)
			os.Exit(1)
		}
		if !rotateDb(*sqlSelect, *sqlUpdate, db, keystorage) {
			os.Exit(1)
		}
	}
}
