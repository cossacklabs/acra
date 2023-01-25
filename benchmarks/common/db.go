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

// Package common provides functions for initialization and running benchmarks
package common

import (
	"database/sql"
	"os"

	// import driver for connect function
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sirupsen/logrus"
)

func connect(connectionString string) *sql.DB {
	db, err := sql.Open("pgx", connectionString)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	return db
}

// Connect return connection to db using env variable PG_CONNECTION_STRING
func Connect() *sql.DB {
	return connect(os.Getenv("PG_CONNECTION_STRING"))
}

// ConnectAcra return connection to acra using env variable ACRA_CONNECTION_STRING
func ConnectAcra() *sql.DB {
	return connect(os.Getenv("ACRA_CONNECTION_STRING"))
}

// DropCreate drop table 'test_data' if exists and create table
// with sequence for primary key. Into this table will be inserted acrastructs
// encrypted with one key and used in read benchmarks
func DropCreate(db *sql.DB) {
	scripts := []string{
		"DROP TABLE IF EXISTS test_data;",
		"DROP SEQUENCE IF EXISTS test_data_seq;",
		"CREATE SEQUENCE test_data_seq START 1;",
		"CREATE TABLE IF NOT EXISTS test_data(id INTEGER PRIMARY KEY DEFAULT nextval('test_data_seq'), data BYTEA);",
	}
	RunScripts(scripts, db)
}

// DropCreateRaw drop table 'test_raw' if exists and create table
// with sequence for primary key. Into this table will be inserted raw data
// without encryption and used in read benchmarks of reading raw data
func DropCreateRaw(db *sql.DB) {
	scripts := []string{
		"DROP TABLE IF EXISTS test_raw;",
		"DROP SEQUENCE IF EXISTS test_raw_seq;",
		"CREATE SEQUENCE test_raw_seq START 1;",
		"CREATE TABLE IF NOT EXISTS test_raw(id INTEGER PRIMARY KEY DEFAULT nextval('test_raw_seq'), data BYTEA);",
	}
	RunScripts(scripts, db)
}

// RunScripts function execute all sql queries in scripts variable using using db
func RunScripts(scripts []string, db *sql.DB) {
	for _, script := range scripts {
		logrus.Debugln(script)
		_, err := db.Exec(script)
		if err != nil {
			logrus.Debugf("Error: on sql - %v\n", script)
			panic(err)
		}
	}
}
