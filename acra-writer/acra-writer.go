/*
Copyright 2018, Cossack Labs Limited

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

// Package acrawriter provides public function CreateAcrastruct for generating
// acrastruct in your applications for encrypting on client-side and inserting
// to database.
//
// https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter
package acrawriter

import (
	"github.com/cossacklabs/acra/acrastruct"

	"github.com/cossacklabs/themis/gothemis/keys"
)

// CreateAcrastruct encrypt your data using acra_public key and context (optional)
// and pack into correct Acrastruct format
func CreateAcrastruct(data []byte, acraPublic *keys.PublicKey, context []byte) ([]byte, error) {
	// due to moving AcraStruct creation to separate package to fix import cycle and aggregate all related functions together
	// there left same function CreateAcrastruct for backward compatibility and call moved implementation
	return acrastruct.CreateAcrastruct(data, acraPublic, context)
}
