package main

import (
	"database/sql"
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/acra/utils"
	_ "github.com/lib/pq"
	"log"
	"math/rand"
	"time"
	"github.com/cossacklabs/acra"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const CONNECTION_STRING string = "user=andrey dbname=acra host=127.0.0.1 port=9494 sslmode=disable disable_prepared_binary_result=yes"

func RandString(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

func main() {
	rand.Seed(time.Now().UnixNano())
	acra_public, err := utils.LoadPublicKey(fmt.Sprintf("%v/client_server.pub", acra.DEFAULT_KEY_DIR_SHORT))
	if err != nil {
		panic(err)
	}
	//some_data := []byte("test data for acra from go")
	some_data := RandString(20)
	fmt.Printf("Generated test data: %v\n", string(some_data))

	acrastruct, err := acrawriter.CreateAcrastruct(some_data, acra_public, nil)

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
	_, err = db.Exec("insert into test (id, data, raw_data) values ($1, $2, $3);", rand.Int31(), acrastruct, string(some_data))
	if err != nil {
		panic(err)
	}

	fmt.Println("Select from db with command: 'SELECT data, raw_data FROM test;'")
	rows, err := db.Query(`SELECT data, raw_data FROM test;`)
	defer rows.Close()
	var data []byte
	var raw_data string
	fmt.Println("data - raw_data")
	for rows.Next() {
		err := rows.Scan(&data, &raw_data)
		if err != nil {
			fmt.Println("ERROR")
			fmt.Println(err)
			return
		}
		fmt.Printf("data: %v\nraw_data: %v\n\n", string(data), string(raw_data))
	}
	fmt.Println("Finish")
}
