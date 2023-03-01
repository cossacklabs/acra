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
	"database/sql"
	"flag"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

func main() {
	mysql := flag.Bool("mysql", false, "Use MySQL driver")
	_ = flag.Bool("postgresql", false, "Use PostgreSQL driver (default if nothing else set)")
	dbname := flag.String("db_name", "acra", "Database name")
	host := flag.String("host", "127.0.0.1", "Database host")
	port := flag.Int("port", 9494, "Database port")
	user := flag.String("db_user", "test", "Database user")
	password := flag.String("db_password", "password", "Database user's password")
	//data := flag.String("data", "", "Data to save")
	//printData := flag.Bool("print", false, "Print data from database")
	//publicKey := flag.String("public_key", "", "Path to public key")
	flag.Parse()

	connectionString := fmt.Sprint("user=test password=test dbname=test host=localhost port=9393 sslmode=disable")
	driver := "postgres"
	if *mysql {
		// username:password@protocol(address)/dbname?param=value
		// https://github.com/go-sql-driver/mysql#dsn-data-source-name
		connectionString = fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", *user, *password, *host, *port, *dbname)
		driver = "mysql"
	}

	//acraPublic, err := utils.LoadPublicKey(*publicKey)
	//if err != nil {
	//	panic(err)
	//}

	db, err := sql.Open(driver, connectionString)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	query := "prepare insert_data (int, text, bytea, int4, int8, text, text) as insert into test_tokenization_default_client_id(id, nullable_column, empty, token_i32, token_i64, token_str, token_email) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err = db.Exec(query)
	if err != nil {
		panic(err)
	}

	query = "execute insert_account ('Artem', 'zhmaka99@gmail.com');"
	_, err = db.Exec(query)
	if err != nil {
		panic(err)
	}

	//query := "prepare read_account as select * from accounts"
	//_, err = db.Exec(query)
	//if err != nil {
	//	panic(err)
	//}
	//
	//query = "execute read_account"
	//
	//rows, err := db.Query(query)
	//defer rows.Close()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//var data []byte
	//var rawData string
	//fmt.Println("data - raw_data")
	//for rows.Next() {
	//	err := rows.Scan(&data, &rawData)
	//	if err != nil {
	//		panic(err)
	//	}
	//	fmt.Printf("data: %v\nraw_data: %v\n\n", string(data), string(rawData))
	//}

	//if *mysql {
	//	query := "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data VARBINARY(1000), raw_data VARCHAR(1000));"
	//	fmt.Printf("Create test table with command: '%v'\n", query)
	//	_, err = db.Exec(query)
	//
	//} else {
	//	query := "CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);"
	//	fmt.Printf("Create test table with command: '%v'\n", query)
	//	_, err = db.Exec(query)
	//}
	//if err != nil {
	//	panic(err)
	//}
	//
	//if *data != "" {
	//	acrastruct, err := acrastruct2.CreateAcrastruct([]byte(*data), acraPublic, nil)
	//	if err != nil {
	//		log.Fatal("can't create acrastruct - ", err)
	//	}
	//	fmt.Println("Insert test data to table")
	//	if *mysql {
	//		_, err = db.Exec("insert into test (id, data, raw_data) values (?, ?, ?);", rand.Int31(), acrastruct, *data)
	//	} else {
	//		_, err = db.Exec("insert into test (id, data, raw_data) values ($1, $2, $3);", rand.Int31(), acrastruct, *data)
	//	}
	//	if err != nil {
	//		panic(err)
	//	}
	//} else if *printData {
	//	query := `SELECT data, raw_data FROM test;`
	//	fmt.Printf("Select from db with command: '%v'\n", query)
	//	rows, err := db.Query(query)
	//	defer rows.Close()
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	var data []byte
	//	var rawData string
	//	fmt.Println("data - raw_data")
	//	for rows.Next() {
	//		err := rows.Scan(&data, &rawData)
	//		if err != nil {
	//			panic(err)
	//		}
	//		fmt.Printf("data: %v\nraw_data: %v\n\n", string(data), string(rawData))
	//	}
	//}

	fmt.Println("Finish")
}
