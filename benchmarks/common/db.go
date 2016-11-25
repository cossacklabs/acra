package common

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"os"
	"github.com/cossacklabs/acra/benchmarks/config"
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

func LoadDataWithoutZone(db *sql.DB){
	var count int
	db.QueryRow("SELECT count(*) FROM test_without_zone;").Scan(&count)
	if count == config.ROW_COUNT{
		fmt.Println("Data in table 'test_without_zone' already exists")
		return
	}
	if count != 0 {
		panic("Incorrect data count exists in table 'test_without_zone'")
	}
	_, err := db.Exec("COPY test_without_zone FROM src/github.com/cossacklabs/acra/benchmarks/fixtures/test_without_zone.sql")
	if err != nil{panic(err)}
}