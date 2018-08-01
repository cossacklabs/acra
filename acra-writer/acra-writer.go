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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
)

// CreateAcrastruct encrypt your data using acra_public key and context (optional)
// and pack into correct Acrastruct format
func CreateAcrastruct(data []byte, acraPublic *keys.PublicKey, context []byte) ([]byte, error) {
	randomKeyPair, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	// generate random symmetric key
	randomKey := make([]byte, base.SYMMETRIC_KEY_SIZE)
	n, err := rand.Read(randomKey)
	if err != nil {
		return nil, err
	}
	if n != base.SYMMETRIC_KEY_SIZE {
		return nil, errors.New("read incorrect num of random bytes")
	}

	// create smessage for encrypting symmetric key
	smessage := message.New(randomKeyPair.Private, acraPublic)
	encryptedKey, err := smessage.Wrap(randomKey)
	if err != nil {
		return nil, err
	}
	// create scell for encrypting data
	scell := cell.New(randomKey, cell.CELL_MODE_SEAL)
	encryptedData, _, err := scell.Protect(data, context)
	if err != nil {
		return nil, err
	}
	utils.FillSlice('0', randomKey)
	// pack acrastruct
	dateLength := make([]byte, base.DATA_LENGTH_SIZE)
	binary.LittleEndian.PutUint64(dateLength, uint64(len(encryptedData)))
	output := make([]byte, len(base.TAG_BEGIN)+base.KEY_BLOCK_LENGTH+base.DATA_LENGTH_SIZE+len(encryptedData))
	output = append(output[:0], base.TAG_BEGIN...)
	output = append(output, randomKeyPair.Public.Value...)
	output = append(output, encryptedKey...)
	output = append(output, dateLength...)
	output = append(output, encryptedData...)
	return output, nil
}
