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
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/themis/gothemis/keys"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

// AcraConnectorAddress default address
var AcraConnectorAddress = "http://127.0.0.1:9191"

// ZoneData stores zone: zoneID and PublicKey
type ZoneData struct {
	ID        string
	PublicKey []byte
}

func main() {
	mysql := flag.Bool("mysql", false, "Use MySQL driver")
	_ = flag.Bool("postgresql", false, "Use PostgreSQL driver (default if nothing else set)")
	dbname := flag.String("db_name", "acra", "Database name")
	host := flag.String("host", "127.0.0.1", "Database host")
	port := flag.Int("port", 9494, "Database port")
	user := flag.String("db_user", "test", "Database user")
	password := flag.String("db_password", "password", "Database user's password")
	data := flag.String("data", "", "Data to save")
	printData := flag.Bool("print", false, "Print data from database")
	zoneID := flag.String("zone_id", "", "Zone ID to fetch")
	flag.Parse()

	connectionString := fmt.Sprintf("user=%v password=%v dbname=%v host=%v port=%v", *user, *password, *dbname, *host, *port)
	driver := "postgres"
	if *mysql {
		// username:password@protocol(address)/dbname?param=value
		// https://github.com/go-sql-driver/mysql#dsn-data-source-name
		connectionString = fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", *user, *password, *host, *port, *dbname)
		driver = "mysql"
	}

	db, err := sql.Open(driver, connectionString)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	if *mysql {
		query := "CREATE TABLE IF NOT EXISTS test_example_with_zone(id INTEGER PRIMARY KEY, zone BINARY(24), data VARBINARY(1000), raw_data VARCHAR(1000));"
		fmt.Printf("Create test_example_with_zone table with command: '%v'\n", query)
		_, err = db.Exec(query)
	} else {
		query := "CREATE TABLE IF NOT EXISTS test_example_with_zone(id INTEGER PRIMARY KEY, zone BYTEA, data BYTEA, raw_data TEXT);"
		fmt.Printf("Create test_example_with_zone table with command: '%v'\n", query)
		_, err = db.Exec(query)
	}
	if err != nil {
		panic(err)
	}

	if *data != "" {
		rand.Seed(time.Now().UnixNano())
		//get new zone over http
		resp, err := http.Get(fmt.Sprintf("%s/getNewZone", AcraConnectorAddress))
		if err != nil {
			panic("Error: getting new zone data (need start Acra with zones (-z) )")
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		zoneData := []byte(body)
		var parsedZoneData ZoneData
		err = json.Unmarshal(zoneData, &parsedZoneData)
		if err != nil {
			panic(err)
		}
		zonePublic := parsedZoneData.PublicKey
		zoneID := []byte(parsedZoneData.ID)

		acrastruct, err := acrawriter.CreateAcrastruct([]byte(*data), &keys.PublicKey{Value: zonePublic}, zoneID)
		if err != nil {
			panic(err)
		}
		fmt.Printf("saved with zone: %v\n", string(zoneID))
		if *mysql {
			_, err = db.Exec("insert into test_example_with_zone (id, zone, data, raw_data) values (?, ?, ?, ?);", rand.Int31(), zoneID, acrastruct, *data)
		} else {
			_, err = db.Exec("insert into test_example_with_zone (id, zone, data, raw_data) values ($1, $2, $3, $4);", rand.Int31(), zoneID, acrastruct, *data)
		}
		if err != nil {
			panic(err)
		}
	} else if *printData {
		var query string
		if *mysql {
			query = `SELECT ?, data, raw_data, zone FROM test_example_with_zone;`
		} else {
			query = `SELECT $1::bytea, data, raw_data, zone FROM test_example_with_zone;`
		}

		fmt.Printf("Select from db with command: '%v'\n", query)
		rows, err := db.Query(query, []byte(*zoneID))
		defer rows.Close()
		if err != nil {
			log.Fatal(err)
		}
		var zone, rawZone, data []byte
		var rawData string
		fmt.Println("zone, data - raw_data")
		for rows.Next() {
			err := rows.Scan(&zone, &data, &rawData, &rawZone)
			if err != nil {
				panic(err)
			}
			fmt.Printf("zone: %v\ndata: %v\nraw_data: %v\nrow zone: %v\n\n", string(zone), string(data), string(rawData), string(rawZone))
		}
	}
	fmt.Println("Finish")
}
