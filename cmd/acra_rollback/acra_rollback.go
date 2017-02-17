// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"bufio"
	"container/list"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	_ "github.com/lib/pq"
	"os"
	"strings"
)

var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acra_rollback")

func ErrorExit(msg string, err error) {
	fmt.Println(utils.ErrorMessage(msg, err))
	os.Exit(1)
}

type BinaryEncoder interface {
	Encode([]byte) string
}

type EscapeEncoder struct{}

func (e *EscapeEncoder) Encode(data []byte) string {
	return QuoteValue(string(postgresql.EncodeToOctal(data)))
}

type HexEncoder struct{}

func (*HexEncoder) Encode(data []byte) string {
	return fmt.Sprintf("E'\\\\x%s'", hex.EncodeToString(data))
}

type Executor interface {
	Execute([]byte)
	Close()
}

type InsertExecutor struct {
	insert_statement *sql.Stmt
}

func NewInsertExecutor(sql string, db *sql.DB) *InsertExecutor {
	stmt, err := db.Prepare(sql)
	if err != nil {
		ErrorExit("Can't prepare sql statement", err)
	}
	return &InsertExecutor{insert_statement: stmt}
}
func (ex *InsertExecutor) Execute(data []byte) {
	_, err := ex.insert_statement.Exec(&data)
	if err != nil {
		ErrorExit("Can't bind args to prepared statement", err)
	}
}
func (ex *InsertExecutor) Close() {
	ex.insert_statement.Close()
}

type WriteToFileExecutor struct {
	encoder BinaryEncoder
	file    *os.File
	sql     string
	writer  *bufio.Writer
}

func NewWriteToFileExecutor(file_path string, sql string, encoder BinaryEncoder) *WriteToFileExecutor {
	abs_path, err := utils.AbsPath(file_path)
	if err != nil {
		ErrorExit("Can't get absolute path for output file", err)
	}
	file, err := os.Create(abs_path)
	if err != nil {
		ErrorExit("Can't create output file", err)
	}
	writer := bufio.NewWriter(file)
	return &WriteToFileExecutor{sql: sql, file: file, writer: writer, encoder: encoder}
}

var PLACEHOLDER = "$1"
var NEWLINE = []byte{'\n'}

func QuoteValue(name string) string {
	end := strings.IndexRune(name, 0)
	if end > -1 {
		name = name[:end]
	}
	return `'` + strings.Replace(name, `'`, `''`, -1) + `'`
}

func (ex *WriteToFileExecutor) Execute(data []byte) {
	encoded := ex.encoder.Encode(data)
	output_sql := strings.Replace(ex.sql, PLACEHOLDER, encoded, 1)
	n, err := ex.writer.Write([]byte(output_sql))
	if err != nil {
		ErrorExit("Can't write to output file", err)
	}
	if n != len(output_sql) {
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
func (ex *WriteToFileExecutor) Close() {
	ex.writer.Flush()
	ex.file.Sync()
	ex.file.Close()
}

func main() {
	keys_dir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")
	client_id := flag.String("client_id", "", "Client id should be name of file with private key")
	connection_string := flag.String("connection_string", "", "Connection string for db (sslmode=disable parameter will be automatically added)")
	sql_select := flag.String("select", "", "Query to fetch data for decryption")
	sql_insert := flag.String("insert", "", "Query for insert decrypted data with placeholders (pg: $n)")
	with_zone := flag.Bool("zonemode", false, "Turn on zon emode")
	output_file := flag.String("output_file", "decrypted.sql", "File for store inserts queries")
	execute := flag.Bool("execute", false, "Execute inserts")
	escape_format := flag.Bool("escape", false, "Escape bytea format")

	cmd.SetLogLevel(cmd.LOG_VERBOSE)

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("Can't parse args", err))
		os.Exit(1)
	}

	if *connection_string == "" {
		fmt.Println("Error: connection_string arg is missing")
		os.Exit(1)
	}
	if !strings.Contains(*connection_string, "sslmode=disable") {
		*connection_string = fmt.Sprintf("%v sslmode=disable", *connection_string)
	}
	if *sql_select == "" {
		fmt.Println("Error: sql_select arg is missing")
		os.Exit(1)
	}
	if *sql_insert == "" {
		fmt.Println("Error: sql_insert arg is missing")
		os.Exit(1)
	}
	abs_keys_dir, err := utils.AbsPath(*keys_dir)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't get absolute path for keys_dir", err))
		os.Exit(1)
	}
	if *output_file == "" && !*execute {
		fmt.Println("Error: output_file missing or execute flag")
		os.Exit(1)
	}
	keystorage, err := keystore.NewFilesystemKeyStore(abs_keys_dir)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't create key store", err))
		os.Exit(1)
	}
	db, err := sql.Open("postgres", *connection_string)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't connect to db", err))
		os.Exit(1)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't connect to db", err))
		os.Exit(1)
	}
	rows, err := db.Query(*sql_select)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage(fmt.Sprintf("error with select query '%v'", *sql_select), err))
		os.Exit(1)
	}
	defer rows.Close()

	executors := list.New()
	if *output_file != "" {
		if *escape_format {
			executors.PushFront(NewWriteToFileExecutor(*output_file, *sql_insert, &EscapeEncoder{}))
		} else {
			executors.PushFront(NewWriteToFileExecutor(*output_file, *sql_insert, &HexEncoder{}))
		}
	}
	if *execute {
		executors.PushFront(NewInsertExecutor(*sql_insert, db))
	}
	for e := executors.Front(); e != nil; e = e.Next() {
		executor := e.Value.(Executor)
		defer executor.Close()
	}

	var data, zone []byte
	var private_key *keys.PrivateKey

	for i := 0; rows.Next(); i++ {
		if *with_zone {
			err = rows.Scan(&zone, &data)
			if err != nil {
				ErrorExit("Can't read zone & data from row %v", err)
			}
			private_key, err = keystorage.GetZonePrivateKey(zone)
			if err != nil {
				fmt.Printf("%v\n", utils.ErrorMessage(fmt.Sprintf("Can't get zone private key for row with number %v", i), err))
				continue
			}
		} else {
			err = rows.Scan(&data)
			if err != nil {
				ErrorExit("Can't read data from row", err)
			}
			private_key, err = keystorage.GetServerDecryptionPrivateKey([]byte(*client_id))
			if err != nil {
				fmt.Printf("%v\n", utils.ErrorMessage(fmt.Sprintf("Can't get private key for row with number %v", i), err))
				continue
			}
		}
		decrypted, err := base.DecryptAcrastruct(data, private_key, zone)
		if err != nil {
			fmt.Printf("%v\n", utils.ErrorMessage(fmt.Sprintf("Can't decrypt acrastruct in row with number %v", i), err))
			continue
		}
		for e := executors.Front(); e != nil; e = e.Next() {
			executor := e.Value.(Executor)
			executor.Execute(decrypted)
		}
	}
}
