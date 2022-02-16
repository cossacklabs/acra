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
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/sirupsen/logrus"
	"os"
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

// DropCreateWithZone drop table 'test_with_zone' if exists and create table
// with sequence for primary key. Into this table will be inserted acrastructs
// encrypted with zone and used in read benchmarks in zonemode
func DropCreateWithZone(db *sql.DB) {
	scripts := []string{
		"DROP TABLE IF EXISTS test_with_zone;",
		"DROP SEQUENCE IF EXISTS test_with_zone_seq;",
		"CREATE SEQUENCE test_with_zone_seq START 1;",
		"CREATE TABLE IF NOT EXISTS test_with_zone(id INTEGER PRIMARY KEY DEFAULT nextval('test_with_zone_seq'), zone BYTEA, data BYTEA);",
	}
	RunScripts(scripts, db)
}

// DropCreateWithoutZone drop table 'test_without_zone' if exists and create table
// with sequence for primary key. Into this table will be inserted acrastructs
// encrypted with one key and used in read benchmarks without zonemode
func DropCreateWithoutZone(db *sql.DB) {
	scripts := []string{
		"DROP TABLE IF EXISTS test_without_zone;",
		"DROP SEQUENCE IF EXISTS test_without_zone_seq;",
		"CREATE SEQUENCE test_without_zone_seq START 1;",
		"CREATE TABLE IF NOT EXISTS test_without_zone(id INTEGER PRIMARY KEY DEFAULT nextval('test_without_zone_seq'), data BYTEA);",
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
