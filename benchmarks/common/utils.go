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
	"math/rand"

	"github.com/cossacklabs/acra/benchmarks/config"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
)

const (
	oneKeyPath   = "src/github.com/cossacklabs/acra/benchmarks/.acrakeys/onekey_server.pub"
	zoneListPath = "src/github.com/cossacklabs/acra/benchmarks/.acrakeys/public_keys.txt"
)

// GenerateData generates random data with MaxDataLength
func GenerateData() ([]byte, error) {
	length := rand.Intn(config.MaxDataLength)
	data := make([]byte, length)
	_, err := data_rand.Read(data)
	return data, err
}

// GetServerOneKeyPublic reads public key
func GetServerOneKeyPublic() *keys.PublicKey {
	publicKey, err := utils.ReadFile(oneKeyPath)
	if err != nil {
		panic(err)
	}
	return &keys.PublicKey{Value: publicKey}
}

// ZoneData stores zone: zoneID and PublicKey
type ZoneData struct {
	ID        []byte
	PublicKey []byte
}

// JSONData stores JSON zone: zoneID and PublicKey
type JSONData struct {
	ID        string
	PublicKey []byte
}

// LoadZones loads zones keys
func LoadZones() []*ZoneData {
	zones := make([]*ZoneData, config.ZoneCount)
	dumpedZoneData, err := utils.ReadFile(zoneListPath)
	if err != nil {
		panic(err)
	}
	for i, zoneData := range bytes.Split(dumpedZoneData, []byte("\n")) {
		jsonData := JSONData{}
		err = json.Unmarshal(zoneData, &jsonData)
		if err != nil {
			panic(err)
		}
		zones[i] = &ZoneData{PublicKey: jsonData.PublicKey, ID: []byte(jsonData.ID)}
	}
	return zones
}
