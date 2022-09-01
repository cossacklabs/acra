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
	data_rand "crypto/rand"
	"math/rand"

	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
)

const (
	oneKeyPath = "./benchmarks/.acrakeys/onekey_server.pub"
)

// GenerateData generates random data with MaxDataLength
func GenerateData() ([]byte, error) {
	// at least 1 byte
	length := 1 + rand.Intn(MaxDataLength)
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
