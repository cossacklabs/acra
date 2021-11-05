/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package fuzz contains simple example that illustrates using Acra with PostgreSQL database:
// 1. AcraWrites encrypts data into AcraStruct.
// 2. Application sends it to database via AcraConnector.
// 3. Application performs SELECT request.
// 4. AcraServer handlers request, decrypts data, returns to application plaintext data.
// 5. Application prints plaintext data.
package fuzz

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	acrastruct2 "github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/themis/gothemis/keys"
	_ "github.com/lib/pq" // pq
	log "github.com/sirupsen/logrus"
)

var dbConnection *sql.DB
var acraConnection *sql.DB
var zone []byte
var zoneKey []byte

func init() {
	var err error
	dbConnection, err = sql.Open("postgres", "user=postgres password=postgres dbname=acratest host=127.0.0.1 port=5432")
	if err != nil {
		log.Fatal(err)
	}
	acraConnection, err = sql.Open("postgres", "user=postgres password=postgres dbname=acratest host=127.0.0.1 port=9494")
	if err != nil {
		log.Fatal(err)
	}
	zone = []byte("ZXCMAkfCrCZzriauuJZ")
	zoneKey, err = base64.StdEncoding.DecodeString("VUVDMgAAAC3iuBM2AtTwKgueCtJIEl3tPK0wzL8pmAiTfaOqXNF1xAX1oX9Q")
	if err != nil {
		log.Fatal(err)
	}
}

// Fuzz is entry point
func Fuzz(data []byte) int {
	var err error
	if len(data) == 0 {
		data = []byte("0")
	}

	acrastruct, err := acrastruct2.CreateAcrastruct(data, &keys.PublicKey{Value: zoneKey}, zone)
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
