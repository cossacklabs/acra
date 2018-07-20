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
package base

import (
	"bytes"
	"encoding/binary"

	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	"github.com/cossacklabs/acra/keystore"
)

const (
	LENGTH_SIZE = 8
)

func DecryptAcrastruct(data []byte, privateKey *keys.PrivateKey, zone []byte) ([]byte, error) {
	if err := ValidateAcraStructLength(data); err != nil {
		return nil, err
	}
	innerData := data[len(TAG_BEGIN):]
	pubkey := &keys.PublicKey{Value: innerData[:PUBLIC_KEY_LENGTH]}
	smessage := message.New(privateKey, pubkey)
	symmetricKey, err := smessage.Unwrap(innerData[PUBLIC_KEY_LENGTH:KEY_BLOCK_LENGTH])
	if err != nil {
		return []byte{}, err
	}
	//
	var length uint64
	// convert from little endian
	err = binary.Read(bytes.NewReader(innerData[KEY_BLOCK_LENGTH:KEY_BLOCK_LENGTH+LENGTH_SIZE]), binary.LittleEndian, &length)
	if err != nil {
		return []byte{}, err
	}
	scell := cell.New(symmetricKey, cell.CELL_MODE_SEAL)
	decrypted, err := scell.Unprotect(innerData[KEY_BLOCK_LENGTH+LENGTH_SIZE:], nil, zone)
	// fill zero symmetric_key
	utils.FillSlice(byte(0), symmetricKey)
	if err != nil {
		return []byte{}, err
	}
	return decrypted, nil
}

func CheckPoisonRecord(data []byte, keystorage keystore.KeyStore)(bool, error){
	poisonKeypair, err := keystorage.GetPoisonKeyPair()
	if err != nil {
		// we can't check on poisoning
		return true, err
	}
	_, err = DecryptAcrastruct(data, poisonKeypair.Private, nil)
	utils.FillSlice(byte(0), poisonKeypair.Private.Value)
	if err == nil {
		// decryption success so it was encrypted with private key for poison records
		return true, nil
	}
	return false, nil
}