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
	"encoding/json"
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/themis/gothemis/keys"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const CONNECTION_STRING string = "user=postgres password=postgres dbname=acra host=127.0.0.1 port=9494 sslmode=disable"

func RandString(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

type ZoneData struct {
	Id         string
	Public_key []byte
}

func main() {
	rand.Seed(time.Now().UnixNano())
	//some_data := []byte("test data for acra from go")
	someData := RandString(20)
	fmt.Printf("Generated test data: %v\n", string(someData))

	//get new zone over http
	resp, err := http.Get("http://127.0.0.1:9191/getNewZone")
	if err != nil {
		panic("Error: getting new zone data (need start Acra with zones (-z) )")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	zoneData := []byte(body)
	//geting zone done
	//	zone_data := []byte(`{"id":"ZXCxJAAWWbelaVCEcNp","public_key":"VUVDMgAAAC3zSak+Ah5wtcenUuD9PorpT8nmlecK2fG78nWsXZ9NEdotnH1B"}`)
	//var parsed_zone_data map[string][]byte
	var parsedZoneData ZoneData
	err = json.Unmarshal(zoneData, &parsedZoneData)
	if err != nil {
		panic(err)
	}
	zonePublic := parsedZoneData.Public_key
	zoneId := []byte(parsedZoneData.Id)

	acrastruct, err := acrawriter.CreateAcrastruct(someData, &keys.PublicKey{Value: zonePublic}, zoneId)
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("postgres", CONNECTION_STRING)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Create test2 table with command: 'CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY, zone BYTEA, data BYTEA, raw_data TEXT);'")
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY, zone BYTEA, data BYTEA, raw_data TEXT);")
	if err != nil {
		panic(err)
	}

	fmt.Println("Insert test data to table")
	_, err = db.Exec("insert into test2 (id, zone, data, raw_data) values ($1, $2, $3, $4);", rand.Int31(), zoneId, acrastruct, string(someData))
	if err != nil {
		panic(err)
	}

	fmt.Println("Select from db with command: 'SELECT zone, data, raw_data FROM test2;'")
	rows, err := db.Query(`SELECT zone, data, raw_data FROM test2;`)
	defer rows.Close()
	if err != nil {
		log.Fatal(err)
	}
	var zone, data []byte
	var rawData string
	fmt.Println("zone, data - raw_data")
	for rows.Next() {
		err := rows.Scan(&zone, &data, &rawData)
		if err != nil {
			fmt.Println("ERROR")
			fmt.Println(err)
			return
		}
		fmt.Printf("zone: %v\ndata: %v\nraw_data: %v\n\n", string(zone), string(data), string(rawData))
	}
	fmt.Println("Finish")
}
