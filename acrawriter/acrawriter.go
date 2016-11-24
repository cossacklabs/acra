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

func CreateAcrastruct(data []byte, acra_public *keys.PublicKey, context []byte) ([]byte, error) {
	random_kp, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		return nil, err
	}
	// generate random symmetric key
	random_key := make([]byte, base.SYMMETRIC_KEY_SIZE)
	n, err := rand.Read(random_key)
	if err != nil {
		return nil, err
	}
	if n != base.SYMMETRIC_KEY_SIZE {
		return nil, errors.New("Read incorrect num of random bytes")
	}

	// create smessage for encrypting symmetric key
	smessage := message.New(random_kp.Private, acra_public)
	encrypted_key, err := smessage.Wrap(random_key)
	if err != nil {
		return nil, err
	}
	// create scell for encrypting data
	scell := cell.New(random_key, cell.CELL_MODE_SEAL)
	encrypted_data, _, err := scell.Protect(data, context)
	if err != nil {
		return nil, err
	}
	utils.FillSlice('0', random_key)
	// pack acrastruct
	data_length := make([]byte, base.DATA_LENGTH_SIZE)
	binary.LittleEndian.PutUint64(data_length, uint64(len(encrypted_data)))
	output := make([]byte, len(base.TAG_BEGIN)+base.KEY_BLOCK_LENGTH+base.DATA_LENGTH_SIZE+len(encrypted_data))
	output = append(output[:0], base.TAG_BEGIN...)
	output = append(output, random_kp.Public.Value...)
	output = append(output, encrypted_key...)
	output = append(output, data_length...)
	output = append(output, encrypted_data...)
	return output, nil
}
