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

package common

import (
	"bytes"
	data_rand "crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/cossacklabs/acra/benchmarks/config"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io/ioutil"
	"math/rand"
)

const (
	// db size will be 100kb * 100000 = 1000mb
	MAX_DATA_LENGTH = 100 * 1024 // 100 kb
)

func GenerateData() ([]byte, error) {
	length := rand.Intn(MAX_DATA_LENGTH)
	data := make([]byte, length)
	_, err := data_rand.Read(data)
	return data, err
}

func GetServerOneKeyPublic() *keys.PublicKey {
	public_key, err := ioutil.ReadFile("src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server.pub")
	if err != nil {
		panic(err)
	}
	return &keys.PublicKey{Value: public_key}
}

type ZoneData struct {
	Id         []byte
	Public_Key []byte
}

func LoadZones() []*ZoneData {
	abs_dir, err := utils.AbsPath("./src/github.com/cossacklabs/acra/benchmarks/.acrakeys")
	if err != nil {
		panic(err)
	}
	zones := make([]*ZoneData, config.ZONE_COUNT)
	dumped_zone_data, err := ioutil.ReadFile(fmt.Sprintf("%v/public_keys.txt", abs_dir))
	if err != nil {
		panic(err)
	}
	for i, zone_data := range bytes.Split(dumped_zone_data, []byte("\n")) {
		json_data := ZoneData{}
		err = json.Unmarshal(zone_data, &json_data)
		if err != nil {
			panic(err)
		}
		zones[i] = &json_data
	}
	return zones
}
