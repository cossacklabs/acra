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

// Package main is entry point for acra-rotate. Acra-rotate provide console utility to rotate private keys and re-encrypt
// data stored in database or as files
package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	"net/url"
	"os"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	filesystemBackendV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem/backend"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"

	log "github.com/sirupsen/logrus"
)

// Constants used by AcraRotate
var (
	// DefaultConfigPath relative path to config which will be parsed as default
	DefaultConfigPath = utils.GetConfigPathByName("acra-rotate")
	ServiceName       = "acra-rotate"
)

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which the keys will be loaded")
	fileMapConfig := flag.String("file_map_config", "", "Path to file with map of <ClientId>: <FilePaths> in json format {\"client_id1\": [\"filepath1\", \"filepath2\"], \"client_id2\": [\"filepath1\", \"filepath2\"]}")
	sqlSelect := flag.String("sql_select", "", "Select query with ? as placeholders where last columns in result must be ClientId and AcraStruct. Other columns will be passed into insert/update query into placeholders")
	sqlUpdate := flag.String("sql_update", "", "Insert/Update query with ? as placeholder where into first will be placed rotated AcraStruct")
	connectionString := flag.String("connection_string", "", "Connection string for DB PostgreSQL(postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}), MySQL ({user}:{password}@tcp({host}:{port})/{dbname})")
	useMysql := flag.Bool("mysql_enable", false, "Handle MySQL connections")
	_ = flag.Bool("postgresql_enable", false, "Handle Postgresql connections")
	dryRun := flag.Bool("dry-run", false, "perform rotation without saving rotated AcraStructs and keys")
	dbTLSEnabled := flag.Bool("tls_database_enabled", false, "Enable TLS for DB")

	logging.SetLogLevel(logging.LogVerbose)

	network.RegisterTLSArgsForService(flag.CommandLine, true, "", network.DatabaseNameConstructorFunc())
	cmd.RegisterRedisKeystoreParameters()
	keyloader.RegisterKeyStoreStrategyParameters()

	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	var keystorage keystore.ServerKeyStore
	if filesystemV2.IsKeyDirectory(*keysDir) {
		keystorage = openKeyStoreV2(*keysDir)
	} else {
		keystorage = openKeyStoreV1(*keysDir)
	}
	if err := crypto.InitRegistry(keystorage); err != nil {
		log.WithError(err).Errorln("Can't initialize crypto registry")
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

		var dbTLSConfig *tls.Config
		if *dbTLSEnabled {
			host, err := network.GetDBURLHost(*connectionString, *useMysql)
			if err != nil {
				log.WithError(err).Errorln("Failed to get DB host from connection URL")
				os.Exit(1)
			}

			dbTLSConfig, err = network.NewTLSConfigByName(flag.CommandLine, "", host, network.DatabaseNameConstructorFunc())
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTransportConfiguration).
					Errorln("Configuration error: can't create database TLS config")
				os.Exit(1)
			}
		}

		var db *sql.DB
		var encoder utils.BinaryEncoder
		if *useMysql {
			if dbTLSConfig != nil {
				connectionURL, err := url.Parse(*connectionString)
				if err != nil {
					log.WithError(err).Errorln("Failed to parse DB connection string")
					os.Exit(1)
				}

				if err := mysql.RegisterTLSConfig("custom", dbTLSConfig); err != nil {
					log.WithError(err).Errorln("Failed to register TLS config")
					os.Exit(1)
				}

				connectioQueryParams := connectionURL.Query()
				connectioQueryParams.Set("tls", "custom")
				connectionURL.RawQuery = connectioQueryParams.Encode()
				*connectionString = connectionURL.String()
			}

			db, err = sql.Open("mysql", *connectionString)
			encoder = &utils.HexEncoder{}
		} else {
			config, err := pgx.ParseConfig(*connectionString)
			if err != nil {
				log.WithError(err).Errorln("Can't connect to db")
				os.Exit(1)
			}

			if dbTLSConfig != nil {
				config.TLSConfig = dbTLSConfig
			}

			db = stdlib.OpenDB(*config)
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

func openKeyStoreV1(dirPath string) keystore.ServerKeyStore {
	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(flag.CommandLine, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
		os.Exit(1)
	}

	keyStore := filesystem.NewCustomFilesystemKeyStore()
	keyStore.KeyDirectory(dirPath)
	keyStore.Encryptor(keyStoreEncryptor)
	if redis := cmd.ParseRedisCLIParameters(); redis.KeysConfigured() {
		redisOptions, err := redis.KeysOptions(flag.CommandLine)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't get Redis options")
			os.Exit(1)
		}
		keyStorage, err := filesystem.NewRedisStorage(redis.HostPort, redis.Password, redis.DBKeys, redisOptions.TLSConfig)
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

func openKeyStoreV2(keyDirPath string) keystore.ServerKeyStore {
	keyStoreSuite, err := keyloader.CreateKeyEncryptorSuite(flag.CommandLine, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore keyStoreSuite")
		os.Exit(1)
	}
	var backend filesystemBackendV2.Backend
	if redis := cmd.ParseRedisCLIParameters(); redis.KeysConfigured() {
		redisOptions, err := redis.KeysOptions(flag.CommandLine)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantInitKeyStore).
				Errorln("Can't get Redis options")
			os.Exit(1)
		}
		config := &filesystemBackendV2.RedisConfig{
			RootDir: keyDirPath,
			Options: redisOptions,
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
	keyDirectory, err := filesystemV2.CustomKeyStore(backend, keyStoreSuite)
	if err != nil {
		log.WithError(err).Error("Failed to initialize key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDirectory)
}
