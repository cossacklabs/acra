package fuzz

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/themis/gothemis/keys"
	_ "github.com/lib/pq"
	"log"
)

var dbConnection *sql.DB
var acraConnection *sql.DB
var zone []byte
var zoneKey []byte

func init() {
	var err error
	dbConnection, err = sql.Open("postgres", "user=postgres password=postgres dbname=acratest host=127.0.0.1 port=5432 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	acraConnection, err = sql.Open("postgres", "user=postgres password=postgres dbname=acratest host=127.0.0.1 port=9494 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	zone = []byte("ZXCMAkfCrCZzriauuJZ")
	zoneKey, err = base64.StdEncoding.DecodeString("VUVDMgAAAC3iuBM2AtTwKgueCtJIEl3tPK0wzL8pmAiTfaOqXNF1xAX1oX9Q")
	if err != nil {
		log.Fatal(err)
	}
}

func Fuzz(data []byte) int {
	var err error
	if len(data) == 0 {
		data = []byte("0")
	}

	acrastruct, err := acrawriter.CreateAcrastruct(data, &keys.PublicKey{Value: zoneKey}, zone)
	if err != nil {
		panic(err)
	}

	var id int64
	err = dbConnection.QueryRow("insert into test (zone, data) values ($1, $2) returning id;", zone, acrastruct).Scan(&id)
	if err != nil {
		panic(err)
	}

	var respZone []byte
	var respData []byte
	err = acraConnection.QueryRow("select zone, data from test where id = $1", id).Scan(&respZone, &respData)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(respZone, zone) {
		panic(fmt.Sprintf("respZone (%q) != zone (%q)", respZone, zone))
	}
	if !bytes.Equal(respData, data) {
		panic(fmt.Sprintf("respData (%q) != data (%q)", respData, data))
	}

	_, err = dbConnection.Exec("delete from test where id=$1", id)
	if err != nil {
		panic(err)
	}
	return 0
}
