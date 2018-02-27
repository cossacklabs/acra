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
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const CONNECTION_STRING string = "user=andrey dbname=acra host=127.0.0.1 port=9494 sslmode=disable"

func RandString(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

func main() {
	rand.Seed(time.Now().UnixNano())
	acraPublic, err := utils.LoadPublicKey(fmt.Sprintf("%v/client_server.pub", keystore.DEFAULT_KEY_DIR_SHORT))
	if err != nil {
		panic(err)
	}
	//some_data := []byte("test data for acra from go")
	someData := RandString(20)
	fmt.Printf("Generated test data: %v\n", string(someData))

	acrastruct, err := acrawriter.CreateAcrastruct(someData, acraPublic, nil)
	if err != nil {
		log.Fatal("can't create acrastruct - ", err)
	}

	db, err := sql.Open("postgres", CONNECTION_STRING)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Create test table with command: 'CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);'")
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);")
	if err != nil {
		panic(err)
	}

	fmt.Println("Insert test data to table")
	_, err = db.Exec("insert into test (id, data, raw_data) values ($1, $2, $3);", rand.Int31(), acrastruct, string(someData))
	if err != nil {
		panic(err)
	}

	fmt.Println("Select from db with command: 'SELECT data, raw_data FROM test;'")
	rows, err := db.Query(`SELECT data, raw_data FROM test;`)
	defer rows.Close()
	if err != nil {
		log.Fatal(err)
	}
	var data []byte
	var rawData string
	fmt.Println("data - raw_data")
	for rows.Next() {
		err := rows.Scan(&data, &rawData)
		if err != nil {
			fmt.Println("ERROR")
			fmt.Println(err)
			return
		}
		fmt.Printf("data: %v\nraw_data: %v\n\n", string(data), string(rawData))
	}
	fmt.Println("Finish")
}
