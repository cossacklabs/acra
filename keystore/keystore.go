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
package keystore

import (
	. "github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"math/rand"
	"time"
)

const (
	DEFAULT_KEY_DIR_SHORT = "./.acrakeys"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generate_id() []byte {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, zone.ZONE_ID_LENGTH)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	//return append(zone.ZONE_ID_BEGIN, append(b, ZONE_ID_END...)...)
	return append(zone.ZONE_ID_BEGIN, b...)
}

type KeyStore interface {
	GetZonePrivateKey(id []byte) (*keys.PrivateKey, error)
	HasZonePrivateKey(id []byte) bool
	GetProxyPublicKey(id []byte) (*keys.PublicKey, error)
	GetServerPrivateKey(id []byte) (*keys.PrivateKey, error)
	// return id, public key, error
	GenerateZoneKey() ([]byte, []byte, error)
}

func GetDefaultKeyDir() (string, error) {
	return AbsPath(DEFAULT_KEY_DIR_SHORT)
}
