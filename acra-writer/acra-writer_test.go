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
package acrawriter_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	"testing"
)

func TestCreateAcrastruct(t *testing.T) {
	acra_kp, err := keys.New(keys.KEYTYPE_EC)
	if err != nil {
		t.Fatal(err)
	}
	DATA_SIZE := 1024
	some_data := make([]byte, DATA_SIZE)

	n, err := rand.Read(some_data)
	if err != nil || n != DATA_SIZE {
		t.Fatal(err)
	}

	acra_struct, err := acrawriter.CreateAcrastruct(some_data, acra_kp.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(acra_struct[:len(base.TAG_BEGIN)], base.TAG_BEGIN) != 0 {
		t.Fatal("Acrastruct has incorrect tag begin")
	}
	public_key := acra_struct[len(base.TAG_BEGIN) : len(base.TAG_BEGIN)+base.PublicKeyLength]
	smessage := message.New(acra_kp.Private, &keys.PublicKey{Value: public_key})
	wrapped_key := acra_struct[len(base.TAG_BEGIN)+base.PublicKeyLength : len(base.TAG_BEGIN)+base.KeyBlockLength]

	unwrapped_key, err := smessage.Unwrap(wrapped_key)
	if err != nil {
		t.Fatal(err)
	}
	scell := cell.New(unwrapped_key, cell.CELL_MODE_SEAL)
	data_length_buf := acra_struct[len(base.TAG_BEGIN)+base.KeyBlockLength : len(base.TAG_BEGIN)+base.KeyBlockLength+base.DataLengthSize]
	data_length := int(binary.LittleEndian.Uint64(data_length_buf))
	data := acra_struct[len(base.TAG_BEGIN)+base.KeyBlockLength+base.DataLengthSize:]
	if len(data) != data_length {
		t.Fatal("Incorrect data length")
	}
	decrypted_data, err := scell.Unprotect(data, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(decrypted_data, some_data) != 0 {
		t.Fatal("Decrypted data not equal to original data")
	}
}
