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

package write

import (
	"database/sql"
	"fmt"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/acra/benchmarks/common"
	"github.com/cossacklabs/acra/benchmarks/config"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"os"
)

func CheckOneKey() {
	keys_path := []string{
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey.pub",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server",
		"src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server.pub",
	}
	for _, key := range keys_path {
		exists, err := utils.FileExists(key)
		if err != nil {
			panic(err)
		}
		if !exists {
			fmt.Printf("Create keypair for acraproxy and for acraserver that will be used in onekey test. Key %v not exists\n", key)
			os.Exit(1)
		}
	}
}
func GetPublicOneKey() *keys.PublicKey {
	public_key, err := utils.LoadPublicKey("src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server.pub")
	if err != nil {
		panic(err)
	}
	return public_key
}

func GenerateAcrastructRowsOneKey(public_key *keys.PublicKey, db *sql.DB) {
	for count := 0; count < config.ROW_COUNT; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}

		acrastruct, err := acrawriter.CreateAcrastruct(data, public_key, nil)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_without_zone(data) VALUES ($1);", &acrastruct)
		if err != nil {
			panic(err)
		}
	}
}

func GenerateDataRows(db *sql.DB) {
	for count := 0; count < config.ROW_COUNT; count++ {
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

func GenerateAcrastructWithZone(db *sql.DB) {
	zones := common.LoadZones()
	for count := 0; count < config.ROW_COUNT; count++ {
		data, err := common.GenerateData()
		if err != nil {
			panic(err)
		}

		zone_data := zones[count%config.ZONE_COUNT]
		acrastruct, err := acrawriter.CreateAcrastruct(data, &keys.PublicKey{Value: zone_data.Public_Key}, zone_data.Id)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO test_with_zone(zone, data) VALUES ($1, $2);", &zone_data.Id, &acrastruct)
		if err != nil {
			panic(err)
		}
	}
}
