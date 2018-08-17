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

// Package poison generates poison record with desired length using provided key. Poison records are the records
// specifically designed and crafted in such a way that they wouldn't be queried by a user
// under normal circumstances. Read more in AcraPoisonRecordsMaker package.
//
// https://github.com/cossacklabs/acra/wiki/Intrusion-detection
package poison

import (
	"crypto/rand"
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/keystore"
	math_rand "math/rand"
	"time"
)

// Poison records length constants
const (
	UseDefaultDataLength = -1
	DefaultDataLength    = 100
)

// CreatePoisonRecord generates AcraStruct encrypted with Poison Record public key
func CreatePoisonRecord(keystore keystore.KeyStore, dataLength int) ([]byte, error) {
	// data length can't be zero
	if dataLength == UseDefaultDataLength {
		math_rand.Seed(time.Now().UnixNano())
		// from 1 to DefaultDataLength
		dataLength = 1 + int(math_rand.Int31n(DefaultDataLength-1))
	}
	poisonKeypair, err := keystore.GetPoisonKeyPair()
	if err != nil {
		return nil, err
	}
	// +1 for excluding 0
	data := make([]byte, dataLength)
	_, err = rand.Read(data)
	if err != nil {
		return nil, err
	}
	return acrawriter.CreateAcrastruct(data, poisonKeypair.Public, nil)
}
