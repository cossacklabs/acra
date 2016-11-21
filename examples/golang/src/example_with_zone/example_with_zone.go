package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/themis/gothemis/keys"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const CONNECTION_STRING string = "user=postgres password=postgres dbname=acra host=127.0.0.1 port=9494 sslmode=disable disable_prepared_binary_result=yes"

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
	some_data := RandString(20)
	fmt.Printf("Generated test data: %v\n", string(some_data))

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
	zone_data := []byte(body)
	//geting zone done
	//	zone_data := []byte(`{"id":"ZXCxJAAWWbelaVCEcNp","public_key":"VUVDMgAAAC3zSak+Ah5wtcenUuD9PorpT8nmlecK2fG78nWsXZ9NEdotnH1B"}`)
	//var parsed_zone_data map[string][]byte
	var parsed_zone_data ZoneData
	err = json.Unmarshal(zone_data, &parsed_zone_data)
	if err != nil {
		panic(err)
	}
	zone_public := parsed_zone_data.Public_key
	zone_id := []byte(parsed_zone_data.Id)

	acrastruct, err := acrawriter.CreateAcrastruct(some_data, &keys.PublicKey{Value: zone_public}, zone_id)
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
	_, err = db.Exec("insert into test2 (id, zone, data, raw_data) values ($1, $2, $3, $4);", rand.Int31(), zone_id, acrastruct, string(some_data))
	if err != nil {
		panic(err)
	}

	fmt.Println("Select from db with command: 'SELECT zone, data, raw_data FROM test2;'")
	rows, err := db.Query(`SELECT zone, data, raw_data FROM test2;`)
	defer rows.Close()
	var zone, data []byte
	var raw_data string
	fmt.Println("zone, data - raw_data")
	for rows.Next() {
		err := rows.Scan(&zone, &data, &raw_data)
		if err != nil {
			fmt.Println("ERROR")
			fmt.Println(err)
			return
		}
		fmt.Printf("zone: %v\ndata: %v\nraw_data: %v\n\n", string(zone), string(data), string(raw_data))
	}
	fmt.Println("Finish")
}
