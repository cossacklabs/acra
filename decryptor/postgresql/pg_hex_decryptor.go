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
package postgresql

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	. "github.com/cossacklabs/acra/utils"
	"io"
	"log"

	"fmt"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
)

// TAG_BEGIN in hex format
//var HEX_TAG_BEGIN = []byte{56, 53, 50, 48, 102, 98}
var HEX_TAG_BEGIN = []byte(hex.EncodeToString(base.TAG_BEGIN))

type PgHexDecryptor struct {
	current_index uint8
	is_with_zone  bool
	// buffer for public_key+SM block
	// 2 hex symbols per byte
	key_block_buffer [base.KEY_BLOCK_LENGTH * 2]byte
	// buffer for decoded from hex public_key+SM block
	//decoded_key_block_buffer [decryptor.KEY_BLOCK_LENGTH]byte
	decoded_key_block_buffer []byte
	//uint64
	length_buf [base.DATA_LENGTH_SIZE]byte
	//uint64 in hex
	hex_length_buf [base.DATA_LENGTH_SIZE * 2]byte
	key_store      keystore.KeyStore
	zone_matcher   *zone.ZoneIdMatcher

	hex_buf []byte
	buf     []byte
	output  []byte

	poison_key       []byte
	callback_storage *base.PoisonCallbackStorage
}

func NewPgHexDecryptor() *PgHexDecryptor {
	return &PgHexDecryptor{
		current_index:            0,
		is_with_zone:             false,
		decoded_key_block_buffer: make([]byte, base.KEY_BLOCK_LENGTH),
	}
}

/* check that buf has free space to append length bytes otherwise extend */
func (decryptor *PgHexDecryptor) checkBuf(buf *[]byte, length int) {
	if buf == nil || len(*buf) < length {
		*buf = make([]byte, length)
	}
}

func (decryptor *PgHexDecryptor) MatchBeginTag(char byte) bool {
	if char == HEX_TAG_BEGIN[decryptor.current_index] {
		decryptor.current_index++
		return true
	} else {
		return false
	}
}

func (decryptor *PgHexDecryptor) IsMatched() bool {
	return int(decryptor.current_index) == len(HEX_TAG_BEGIN)
}
func (decryptor *PgHexDecryptor) Reset() {
	decryptor.current_index = 0
}
func (decryptor *PgHexDecryptor) GetMatched() []byte {
	return HEX_TAG_BEGIN[:decryptor.current_index]
}
func (decryptor *PgHexDecryptor) ReadSymmetricKey(private_key *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	n, err := io.ReadFull(reader, decryptor.key_block_buffer[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.key_block_buffer[:n], base.FAKE_ACRA_STRUCT
		} else {
			return nil, decryptor.key_block_buffer[:n], err
		}
	}
	if n != hex.EncodedLen(base.KEY_BLOCK_LENGTH) {
		log.Printf("Warning: %v\n", ErrorMessage("can't decode hex data", err))
		return nil, decryptor.key_block_buffer[:n], base.FAKE_ACRA_STRUCT
	}
	_, err = hex.Decode(decryptor.decoded_key_block_buffer[:], decryptor.key_block_buffer[:])
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't decode hex data", err))
		return nil, decryptor.key_block_buffer[:n], base.FAKE_ACRA_STRUCT
	}
	pubkey := &keys.PublicKey{Value: decryptor.decoded_key_block_buffer[:base.PUBLIC_KEY_LENGTH]}

	smessage := message.New(private_key, pubkey)
	symmetric_key, err := smessage.Unwrap(decryptor.decoded_key_block_buffer[base.PUBLIC_KEY_LENGTH:])
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't unwrap symmetric key", err))
		return nil, decryptor.key_block_buffer[:n], base.FAKE_ACRA_STRUCT
	}
	return symmetric_key, decryptor.key_block_buffer[:n], nil
}

func (decryptor *PgHexDecryptor) readDataLength(reader io.Reader) (uint64, []byte, error) {
	var length uint64
	len_count, err := io.ReadFull(reader, decryptor.hex_length_buf[:])
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't read data length", err))
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return 0, decryptor.hex_length_buf[:len_count], base.FAKE_ACRA_STRUCT
		} else {
			return 0, decryptor.hex_length_buf[:len_count], err
		}
	}
	if len_count != len(decryptor.hex_length_buf) {
		log.Printf("Warning: incorrect length count, %v!=%v\n", len_count, len(decryptor.length_buf))
		return 0, decryptor.hex_length_buf[:len_count], base.FAKE_ACRA_STRUCT
	}

	// decode hex length to binary length
	n, err := hex.Decode(decryptor.length_buf[:], decryptor.hex_length_buf[:])
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't decode hex data", err))
		return 0, decryptor.hex_length_buf[:len_count], base.FAKE_ACRA_STRUCT
	}
	if n != len(decryptor.length_buf) {
		log.Printf("Warning: %v\n", ErrorMessage("can't decode hex data", err))
		return 0, decryptor.hex_length_buf[:len_count], base.FAKE_ACRA_STRUCT
	}
	// convert from little endian
	binary.Read(bytes.NewReader(decryptor.length_buf[:]), binary.LittleEndian, &length)
	return length, decryptor.hex_length_buf[:], nil
}
func (decryptor *PgHexDecryptor) readScellData(length int, reader io.Reader) ([]byte, []byte, error) {
	hex_length := hex.EncodedLen(int(length))
	decryptor.checkBuf(&decryptor.hex_buf, hex_length)
	decryptor.checkBuf(&decryptor.buf, int(length))
	n, err := io.ReadFull(reader, decryptor.hex_buf[:hex_length])
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage(fmt.Sprintf("can't read scell data with passed length=%v", length), err))
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.hex_buf[:n], base.FAKE_ACRA_STRUCT
		} else {
			return nil, decryptor.hex_buf[:n], err
		}
	}
	if n != hex.EncodedLen(length) {
		return nil, decryptor.hex_buf[:n], base.FAKE_ACRA_STRUCT
	}
	n, err = hex.Decode(decryptor.buf[:int(length)], decryptor.hex_buf[:hex_length])
	if err != nil {
		log.Printf("Warning: %v\n", ErrorMessage("can't decode hex data", err))
		return nil, decryptor.hex_buf[:n], base.FAKE_ACRA_STRUCT
	}
	if n != int(length) {
		log.Printf("Warning: %v\n", ErrorMessage("can't decode hex data", err))
		return nil, decryptor.hex_buf[:n], base.FAKE_ACRA_STRUCT
	}
	return decryptor.buf[:int(length)], decryptor.hex_buf[:hex_length], nil
}

func (*PgHexDecryptor) getFullDataLength(data_length uint64) int {
	// original data is tag_begin+key_block+data_length+data
	// output data length should be hex(original_data)
	return hex.EncodedLen(len(base.TAG_BEGIN) + base.KEY_BLOCK_LENGTH + 8 + int(data_length))
}

func (decryptor *PgHexDecryptor) ReadData(symmetric_key, zone_id []byte, reader io.Reader) ([]byte, error) {
	length, hex_length_buf, err := decryptor.readDataLength(reader)
	if err != nil {
		return hex_length_buf, err
	}
	data, hex_data, err := decryptor.readScellData(int(length), reader)
	if err != nil {
		return append(hex_length_buf, hex_data...), err
	}

	scell := cell.New(symmetric_key, cell.CELL_MODE_SEAL)

	decrypted, err := scell.Unprotect(data, nil, zone_id)
	data = nil
	// fill zero symmetric_key
	FillSlice(byte(0), symmetric_key)
	if err != nil {
		return append(hex_length_buf, hex_data...), base.FAKE_ACRA_STRUCT
	}

	output_length := hex.EncodedLen(len(decrypted))
	decryptor.checkBuf(&decryptor.output, output_length)
	hex.Encode(decryptor.output[:output_length], decrypted)
	decrypted = nil
	return decryptor.output[:output_length], nil
}

func (decryptor *PgHexDecryptor) GetTagBeginLength() int {
	return len(HEX_TAG_BEGIN)
}
