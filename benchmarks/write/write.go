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

// Package write provides useful functions that used in benchmarks for testing
// writes to db
package write

import (
	"database/sql"
	"fmt"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"os"
)

// CheckOneKey checks that all key pairs for client id <onekey> exists
func CheckOneKey() {
	keysPath := []string{
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey.pub",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server.pub",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_storage",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_storage.pub",
	}
	for _, key := range keysPath {
		exists, err := utils.FileExists(key)
		if err != nil {
			panic(err)
		}
		if !exists {
			fmt.Printf("Create keypair for AcraConnector and for AcraServer that will be used in onekey test. Key %v not exists\n", key)
			os.Exit(1)
		}
	}
}

// GetPublicOneKey load and return public key for acra-writer <onekey_storage.pub>
func GetPublicOneKey() *keys.PublicKey {
	publicKey, err := utils.LoadPublicKey("src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_storage.pub")
	if err != nil {
		panic(err)
	}
	return publicKey
}

// GenerateAcrastructRowsOneKey generate RowCount acrastructs with random data
// using <onekey_storage.pub> and insert to db
func GenerateAcrastructRowsOneKey(publicKey *keys.PublicKey, db *sql.DB) {
	for count := 0; count < common.RowCount; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}

		acrastruct, err := acrastruct.CreateAcrastruct(data, publicKey, nil)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_without_zone(data) VALUES ($1);", &acrastruct)
		if err != nil {
			panic(err)
		}
	}
}

// GenerateDataRows generate RowCount raw random data and insert to db
func GenerateDataRows(db *sql.DB) {
	for count := 0; count < common.RowCount; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_raw(data) VALUES ($1);", &data)
		if err != nil {
			panic(err)
		}
	}
}

// GenerateAcrastructWithZone generate RowCount acrastructs using sequentially
// all ZoneCount zones
func GenerateAcrastructWithZone(db *sql.DB) {
	zones := common.LoadZones()
	for count := 0; count < common.RowCount; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}

		zoneData := zones[count%common.ZoneCount]
		acraStruct, err := acrastruct.CreateAcrastruct(data, &keys.PublicKey{Value: zoneData.PublicKey}, zoneData.ID)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_with_zone(zone, data) VALUES ($1, $2);", &zoneData.ID, &acraStruct)
		if err != nil {
			panic(err)
		}
	}
}
