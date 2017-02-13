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
package poison

import (
	"crypto/rand"
	"github.com/cossacklabs/acra/acrawriter"
	"github.com/cossacklabs/acra/keystore"
	math_rand "math/rand"
	"time"
)

const (
	DEFAULT_DATA_LENGTH = -1
	MAX_DATA_LENGTH     = 100
)

func CreatePoisonRecord(keystore keystore.KeyStore, data_length int) ([]byte, error) {
	// data length can't be zero
	if data_length == DEFAULT_DATA_LENGTH {
		math_rand.Seed(time.Now().UnixNano())
		// from 1 to MAX_DATA_LENGTH
		data_length = 1 + int(math_rand.Int31n(MAX_DATA_LENGTH-1))
	}
	poison_keypair, err := keystore.GetPoisonKeyPair()
	if err != nil {
		return nil, err
	}
	// +1 for excluding 0
	data := make([]byte, data_length)
	_, err = rand.Read(data)
	if err != nil {
		return nil, err
	}
	return acrawriter.CreateAcrastruct(data, poison_keypair.Public, nil)
}
