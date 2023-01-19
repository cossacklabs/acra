/*
Copyright 2016, Cossack Labs Limited

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

// Package main is entry point for AcraRollback utility. AcraRollback allows users to decrypt data from database:
// it generates a clean SQL dump from an existing protected one. To decrypt the protected data, the utility makes
// a request to users database using SELECT query, then decrypts data, then generates the SQL dump which it can execute,
// or write to file.
//
// https://github.com/cossacklabs/acra/wiki/AcraRollback
package main

import (
	"bufio"
	"container/list"
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	log "github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/keystore/filesystem"
	"github.com/cossacklabs/acra/keystore/keyloader"
	keystoreV2 "github.com/cossacklabs/acra/keystore/v2/keystore"
	filesystemV2 "github.com/cossacklabs/acra/keystore/v2/keystore/filesystem"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
)

// Constants used by AcraRollback
var (
	// defaultConfigPath relative path to config which will be parsed as default
	defaultConfigPath = utils.GetConfigPathByName("acra-rollback")
	serviceName       = "acra-rollback"
)

// ErrorExit prints error and exits.
func ErrorExit(msg string, err error) {
	log.WithError(err).Errorln(msg)
	os.Exit(1)
}

// Executor interface for any executor.
type Executor interface {
	Execute([]byte)
	Close()
}

// InsertExecutor will run Insert statement
type InsertExecutor struct {
	insertStatement *sql.Stmt
}

// NewInsertExecutor creates new executor for Insert statements
func NewInsertExecutor(sql string, db *sql.DB) *InsertExecutor {
	stmt, err := db.Prepare(sql)
	if err != nil {
		ErrorExit("can't prepare sql statement", err)
	}
	return &InsertExecutor{insertStatement: stmt}
}

// Execute inserts
func (ex *InsertExecutor) Execute(data []byte) {
	_, err := ex.insertStatement.Exec(&data)
	if err != nil {
		ErrorExit("can't bind args to prepared statement", err)
	}
}

// Close executor
func (ex *InsertExecutor) Close() {
	ex.insertStatement.Close()
}

// WriteToFileExecutor writes to file
type WriteToFileExecutor struct {
	encoder utils.BinaryEncoder
	file    *os.File
	sql     string
	writer  *bufio.Writer
}

// NewWriteToFileExecutor creates new object ready to write encoded sql to filePath
func NewWriteToFileExecutor(filePath string, sql string, encoder utils.BinaryEncoder) *WriteToFileExecutor {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		ErrorExit("can't get absolute path for output file", err)
	}
	file, err := os.Create(absPath)
	if err != nil {
		ErrorExit("can't create output file", err)
	}
	writer := bufio.NewWriter(file)
	return &WriteToFileExecutor{sql: sql, file: file, writer: writer, encoder: encoder}
}

// PLACEHOLDER char
var PLACEHOLDER = "$1"

// NEWLINE char
var NEWLINE = []byte{'\n'}

// Execute write to file
func (ex *WriteToFileExecutor) Execute(data []byte) {
	encoded := ex.encoder.EncodeToString(data)
	outputSQL := strings.Replace(ex.sql, PLACEHOLDER, encoded, 1)
	n, err := ex.writer.Write([]byte(outputSQL))
	if err != nil {
		ErrorExit("Can't write to output file", err)
	}
	if n != len(outputSQL) {
		fmt.Println("Incorrect write count")
		os.Exit(1)
	}
	n, err = ex.writer.Write(NEWLINE)
	if err != nil {
		ErrorExit("Can't write newline char to output file", err)
	}
	if n != 1 {
		fmt.Println("Incorrect write count")
		os.Exit(1)
	}
}

// Close file
func (ex *WriteToFileExecutor) Close() {
	if err := ex.writer.Flush(); err != nil {
		log.WithError(err).Errorln("Can't flush data in writer")
	}
	if err := ex.file.Sync(); err != nil {
		log.WithError(err).Errorln("Can't sync file")
	}
	if err := ex.file.Close(); err != nil {
		log.WithError(err).Errorln("Can't close file")
	}
}

func main() {
	keysDir := flag.String("keys_dir", keystore.DefaultKeyDirShort, "Folder from which the keys will be loaded")
	clientID := flag.String("client_id", "", "Client ID should be name of file with private key")
	connectionString := flag.String("connection_string", "", "Connection string for DB PostgreSQL(postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}), MySQL ({user}:{password}@tcp({host}:{port})/{dbname})")
	sqlSelect := flag.String("select", "", "Query to fetch data for decryption")
	sqlInsert := flag.String("insert", "", "Query for insert decrypted data with placeholders (pg: $n, mysql: ?)")
	outputFile := flag.String("output_file", "decrypted.sql", "File for store inserts queries")
	execute := flag.Bool("execute", false, "Execute inserts")
	escapeFormat := flag.Bool("escape", false, "Escape bytea format")
	useMysql := flag.Bool("mysql_enable", false, "Handle MySQL connections")
	usePostgresql := flag.Bool("postgresql_enable", false, "Handle Postgresql connections")
	dbTLSEnabled := flag.Bool("tls_database_enabled", false, "Enable TLS for DB")

	network.RegisterTLSArgsForService(flag.CommandLine, true, "", network.DatabaseNameConstructorFunc())
	network.RegisterTLSBaseArgs(flag.CommandLine)
	keyloader.RegisterKeyStoreStrategyParameters()
	logging.SetLogLevel(logging.LogVerbose)

	err := cmd.Parse(defaultConfigPath, serviceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	twoDrivers := *useMysql && *usePostgresql
	noDrivers := !(*useMysql || *usePostgresql)
	if twoDrivers || noDrivers {
		log.Errorln("You must pass only --mysql_enable or --postgresql_enable (one required)")
		os.Exit(1)
	}
	if *useMysql {
		PLACEHOLDER = "?"
	}

	if !strings.Contains(*sqlInsert, PLACEHOLDER) {
		log.Errorln("SQL INSERT statement doesn't contain any placeholders")
		os.Exit(1)
	}

	if *connectionString == "" {
		log.Errorln("Connection_string arg is missing")
		os.Exit(1)
	}

	cmd.ValidateClientID(*clientID)

	if *sqlSelect == "" {
		log.Errorln("Sql_select arg is missing")
		os.Exit(1)
	}
	if *sqlInsert == "" {
		log.Errorln("Sql_insert arg is missing")
		os.Exit(1)
	}

	if *outputFile == "" && !*execute {
		log.Errorln("Output_file missing or execute flag")
		os.Exit(1)
	}

	var keystorage keystore.DecryptionKeyStore
	if filesystemV2.IsKeyDirectory(*keysDir) {
		keystorage = openKeyStoreV2(*keysDir)
	} else {
		keystorage = openKeyStoreV1(*keysDir)
	}

	var dbTLSConfig *tls.Config
	if *dbTLSEnabled {
		host, err := network.GetDriverConnectionStringHost(*connectionString, *useMysql)
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
		if err != nil {
			log.WithError(err).Errorln("Can't connect to db")
			os.Exit(1)
		}
	} else {
		config, err := pgx.ParseConfig(*connectionString)
		if err != nil {
			log.WithError(err).Errorln("Can't parse config ")
			os.Exit(1)
		}

		if dbTLSConfig != nil {
			config.TLSConfig = dbTLSConfig
		}

		db = stdlib.OpenDB(*config)
	}

	defer db.Close()
	err = db.Ping()
	if err != nil {
		log.WithError(err).Errorln("Can't connect to db")
		os.Exit(1)
	}
	rows, err := db.Query(*sqlSelect)
	if err != nil {
		log.WithError(err).Errorf("Error with select query '%v'", *sqlSelect)
		os.Exit(1)
	}
	defer rows.Close()

	executors := list.New()
	if *outputFile != "" {
		if *useMysql {
			executors.PushFront(NewWriteToFileExecutor(*outputFile, *sqlInsert, &utils.MysqlEncoder{}))
		} else {
			if *escapeFormat {
				executors.PushFront(NewWriteToFileExecutor(*outputFile, *sqlInsert, &utils.EscapeEncoder{}))
			} else {
				executors.PushFront(NewWriteToFileExecutor(*outputFile, *sqlInsert, &utils.HexEncoder{}))
			}
		}
	}
	if *execute {
		executors.PushFront(NewInsertExecutor(*sqlInsert, db))
	}
	for e := executors.Front(); e != nil; e = e.Next() {
		executor := e.Value.(Executor)
		defer executor.Close()
	}

	for i := 0; rows.Next(); i++ {
		var data []byte
		err = rows.Scan(&data)
		if err != nil {
			ErrorExit("Can't read data from row", err)
		}
		privateKeys, err := keystorage.GetServerDecryptionPrivateKeys([]byte(*clientID))
		if err != nil {
			log.WithError(err).Errorf("Can't get private key for row with number %v", i)
			continue
		}

		decrypted, err := acrastruct.DecryptRotatedAcrastruct(data, privateKeys, nil)
		utils.ZeroizePrivateKeys(privateKeys)
		if err != nil {
			log.WithError(err).Errorf("Can't decrypt acrastruct in row with number %v", i)
			continue
		}
		for e := executors.Front(); e != nil; e = e.Next() {
			executor := e.Value.(Executor)
			executor.Execute(decrypted)
		}
	}
}

func openKeyStoreV1(keysDir string) keystore.DecryptionKeyStore {
	var keyStoreEncryptor keystore.KeyEncryptor
	keyStoreEncryptor, err := keyloader.CreateKeyEncryptor(flag.CommandLine, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore KeyEncryptor")
		os.Exit(1)
	}

	keystorage, err := filesystem.NewFilesystemKeyStore(keysDir, keyStoreEncryptor)
	if err != nil {
		log.WithError(err).Errorln("Can't initialize keystore")
		os.Exit(1)
	}
	return keystorage
}

func openKeyStoreV2(keyDirPath string) keystore.DecryptionKeyStore {
	keyStoreSuite, err := keyloader.CreateKeyEncryptorSuite(flag.CommandLine, "")
	if err != nil {
		log.WithError(err).Errorln("Can't init keystore keyStoreSuite")
		os.Exit(1)
	}
	keyDir, err := filesystemV2.OpenDirectoryRW(keyDirPath, keyStoreSuite)
	if err != nil {
		log.WithError(err).WithField("path", keyDirPath).Error("cannot open key directory")
		os.Exit(1)
	}
	return keystoreV2.NewServerKeyStore(keyDir)
}
