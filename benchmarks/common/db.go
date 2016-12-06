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

package common

import (
	"database/sql"
	"fmt"
	"github.com/cossacklabs/acra/benchmarks/config"
	_ "github.com/lib/pq"
	"os"
)

func connect(connection_string string) *sql.DB {
	db, err := sql.Open("postgres", connection_string)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	return db
}

//export ACRA_CONNECTION_STRING='dbname=benchmark user=postgres password=postgres host=127.0.0.1 port=9494 sslmode=disable'
//export PG_CONNECTION_STRING='dbname=benchmark user=postgres password=postgres host=172.17.0.1 port=5433 sslmode=disable'
func Connect() *sql.DB {
	connection_string := os.Getenv("PG_CONNECTION_STRING")
	return connect(connection_string)
}

func ConnectAcra() *sql.DB {
	connection_string := os.Getenv("ACRA_CONNECTION_STRING")
	return connect(connection_string)
}

func DropCreateWithZone(db *sql.DB) {
	scripts := []string{
		"DROP TABLE IF EXISTS test_with_zone;",
		"DROP SEQUENCE IF EXISTS test_with_zone_seq;",
		"CREATE SEQUENCE test_with_zone_seq START 1;",
		"CREATE TABLE IF NOT EXISTS test_with_zone(id INTEGER PRIMARY KEY DEFAULT nextval('test_with_zone_seq'), zone BYTEA, data BYTEA);",
	}
	RunScripts(scripts, db)
}

func DropCreateWithoutZone(db *sql.DB) {
	scripts := []string{
		"DROP TABLE IF EXISTS test_without_zone;",
		"DROP SEQUENCE IF EXISTS test_without_zone_seq;",
		"CREATE SEQUENCE test_without_zone_seq START 1;",
		"CREATE TABLE IF NOT EXISTS test_without_zone(id INTEGER PRIMARY KEY DEFAULT nextval('test_without_zone_seq'), data BYTEA);",
	}
	RunScripts(scripts, db)
}

func DropCreateRaw(db *sql.DB) {
	scripts := []string{
		"DROP TABLE IF EXISTS test_raw;",
		"DROP SEQUENCE IF EXISTS test_raw_seq;",
		"CREATE SEQUENCE test_raw_seq START 1;",
		"CREATE TABLE IF NOT EXISTS test_raw(id INTEGER PRIMARY KEY DEFAULT nextval('test_raw_seq'), data BYTEA);",
	}
	RunScripts(scripts, db)
}

func RunScripts(scripts []string, db *sql.DB) {
	for _, script := range scripts {
		fmt.Println(script)
		_, err := db.Exec(script)
		if err != nil {
			fmt.Printf("Error: on sql - %v\n", script)
			panic(err)
		}
	}
}

func IsExistsData(tablename string, db *sql.DB) bool {
	var count int
	db.QueryRow(fmt.Sprintf("SELECT count(*) FROM %s;", tablename)).Scan(&count)
	if count == config.ROW_COUNT {
		fmt.Printf("Data in table '%s' already exists\n", tablename)
		return true
	}
	return false
}
