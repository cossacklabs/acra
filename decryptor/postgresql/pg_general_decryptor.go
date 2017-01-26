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
	"encoding/hex"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/binary"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io"
	"log"
)

type PgDecryptor struct {
	is_with_zone      bool
	is_whole_match    bool
	key_store         keystore.KeyStore
	zone_matcher      *zone.ZoneIdMatcher
	pg_decryptor      base.DataDecryptor
	binary_decryptor  base.DataDecryptor
	matched_decryptor base.DataDecryptor

	poison_key       []byte
	client_id        []byte
	match_buffer     []byte
	match_index      int
	callback_storage *base.PoisonCallbackStorage
}

func NewPgDecryptor(client_id []byte, decryptor base.DataDecryptor) *PgDecryptor {
	return &PgDecryptor{
		is_with_zone:     false,
		pg_decryptor:     decryptor,
		binary_decryptor: binary.NewBinaryDecryptor(client_id),
		client_id:        client_id,
		// longest tag (escape) + bin
		match_buffer:   make([]byte, len(ESCAPE_TAG_BEGIN)+len(base.TAG_BEGIN)),
		match_index:    0,
		is_whole_match: true,
	}
}

func (decryptor *PgDecryptor) SetWithZone(b bool) {
	decryptor.is_with_zone = b
}

func (decryptor *PgDecryptor) SetZoneMatcher(zone_matcher *zone.ZoneIdMatcher) {
	decryptor.zone_matcher = zone_matcher
}

func (decryptor *PgDecryptor) IsMatchedZone() bool {
	return decryptor.zone_matcher.IsMatched() && decryptor.key_store.HasZonePrivateKey(decryptor.zone_matcher.GetZoneId())
}

func (decryptor *PgDecryptor) MatchZone(b byte) bool {
	return decryptor.zone_matcher.Match(b)
}

func (decryptor *PgDecryptor) GetMatchedZoneId() []byte {
	if decryptor.IsWithZone() {
		return decryptor.zone_matcher.GetZoneId()
	} else {
		return nil
	}
}

func (decryptor *PgDecryptor) ResetZoneMatch() {
	if decryptor.zone_matcher != nil {
		decryptor.zone_matcher.Reset()
	}
}

func (decryptor *PgDecryptor) MatchBeginTag(char byte) bool {
	/* should be called two decryptors */
	matched := decryptor.pg_decryptor.MatchBeginTag(char)
	matched = decryptor.binary_decryptor.MatchBeginTag(char) || matched
	if matched {
		decryptor.match_buffer[decryptor.match_index] = char
		decryptor.match_index++
	}
	return matched
}

func (decryptor *PgDecryptor) IsWithZone() bool {
	return decryptor.is_with_zone
}

func (decryptor *PgDecryptor) IsMatched() bool {
	// TODO here pg_decryptor has higher priority than binary_decryptor
	// but can be case when begin tag is equal for binary and escape formats
	// in this case may be error in stream mode
	if decryptor.pg_decryptor.IsMatched() {
		log.Println("Debug: matched pg decryptor")
		decryptor.matched_decryptor = decryptor.pg_decryptor
		return true
	} else if decryptor.binary_decryptor.IsMatched() {
		log.Println("Debug: matched binary decryptor")
		decryptor.matched_decryptor = decryptor.binary_decryptor
		return true
	} else {
		decryptor.matched_decryptor = nil
		return false
	}
}
func (decryptor *PgDecryptor) Reset() {
	decryptor.matched_decryptor = nil
	decryptor.binary_decryptor.Reset()
	decryptor.pg_decryptor.Reset()
	decryptor.match_index = 0
}
func (decryptor *PgDecryptor) GetMatched() []byte {
	return decryptor.match_buffer[:decryptor.match_index]
}

func (decryptor *PgDecryptor) ReadSymmetricKey(private_key *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	symmetric_key, raw_data, err := decryptor.matched_decryptor.ReadSymmetricKey(private_key, reader)
	if err != nil {
		return symmetric_key, raw_data, err
	}
	return symmetric_key, raw_data, nil
}

func (decryptor *PgDecryptor) ReadData(symmetric_key, zone_id []byte, reader io.Reader) ([]byte, error) {
	/* due to using two decryptors can be case when one decryptor match 2 bytes
	from TAG_BEGIN then didn't match anymore but another decryptor matched at
	this time and was successfully used for decryption, we need return 2 bytes
	matched and buffered by first decryptor and decrypted data from the second

	for example case of matching begin tag:
	BEGIN_TA - failed decryptor1
	00BEGIN_TAG - successful decryptor2
	in this case first decryptor1 matched not full begin_tag and failed on 'G' but
	at this time was matched decryptor2 and successfully matched next bytes and decrypted data
	so we need return diff of two matches 'BE' and decrypted data
	*/

	// take length of fully matched tag begin (each decryptor match tag begin with different length)
	correct_match_begin_tag_length := len(decryptor.matched_decryptor.GetMatched())
	// take diff count of matched between two decryptors
	false_buffered_begin_tag_length := decryptor.match_index - correct_match_begin_tag_length
	if false_buffered_begin_tag_length > 0 {
		log.Printf("Debug: return with false matched %v bytes\n", false_buffered_begin_tag_length)
		decrypted, err := decryptor.matched_decryptor.ReadData(symmetric_key, zone_id, reader)
		return append(decryptor.match_buffer[:false_buffered_begin_tag_length], decrypted...), err
	} else {
		return decryptor.matched_decryptor.ReadData(symmetric_key, zone_id, reader)
	}
}

func (decryptor *PgDecryptor) SetKeyStore(store keystore.KeyStore) {
	decryptor.key_store = store
}

func (decryptor *PgDecryptor) GetPrivateKey() (*keys.PrivateKey, error) {
	if decryptor.IsWithZone() {
		return decryptor.key_store.GetZonePrivateKey(decryptor.GetMatchedZoneId())
	} else {
		return decryptor.key_store.GetServerDecryptionPrivateKey(decryptor.client_id)
	}
}

func (decryptor *PgDecryptor) GetPoisonCallbackStorage() *base.PoisonCallbackStorage {
	return decryptor.callback_storage
}

func (decryptor *PgDecryptor) SetPoisonCallbackStorage(storage *base.PoisonCallbackStorage) {
	decryptor.callback_storage = storage
}

func (decryptor *PgDecryptor) IsWholeMatch() bool {
	return decryptor.is_whole_match
}

func (decryptor *PgDecryptor) SetWholeMatch(value bool) {
	decryptor.is_whole_match = value
}

func (decryptor *PgDecryptor) MatchZoneBlock(block []byte) {
	if _, ok := decryptor.pg_decryptor.(*PgHexDecryptor); ok && bytes.Equal(block[:2], HEX_PREFIX) {
		block = block[2:]
	}
	for _, c := range block {
		if !decryptor.MatchZone(c) {
			return
		}
	}
}

var HEX_PREFIX = []byte{'\\', 'x'}

func (decryptor *PgDecryptor) SkipBeginInBlock(block []byte) ([]byte, error) {
	_, ok := decryptor.pg_decryptor.(*PgHexDecryptor)
	// in hex format can be \x bytes at beginning
	// we need skip them for correct matching begin tag
	n := 0
	if ok && bytes.Equal(block[:2], HEX_PREFIX) {
		block = block[2:]
		for _, c := range block {
			if !decryptor.pg_decryptor.MatchBeginTag(c) {
				return []byte{}, base.ErrFakeAcraStruct
			}
			n++
			if decryptor.pg_decryptor.IsMatched() {
				break
			}
		}
	} else {
		for _, c := range block {
			if !decryptor.MatchBeginTag(c) {
				return []byte{}, base.ErrFakeAcraStruct
			}
			n++
			if decryptor.IsMatched() {
				break
			}
		}
	}
	if !decryptor.IsMatched() {
		return []byte{}, base.ErrFakeAcraStruct
	}
	return block[n:], nil
}

func (decryptor *PgDecryptor) DecryptBlock(block []byte) ([]byte, error) {
	data_block, err := decryptor.SkipBeginInBlock(block)
	if err != nil {
		return []byte{}, err
	}

	reader := bytes.NewReader(data_block)
	private_key, err := decryptor.GetPrivateKey()
	if err != nil {
		return []byte{}, err
	}
	key, _, err := decryptor.ReadSymmetricKey(private_key, reader)
	if err != nil {
		return []byte{}, err
	}
	data, err := decryptor.ReadData(key, decryptor.GetMatchedZoneId(), reader)
	if err != nil {
		return []byte{}, err
	}
	if _, ok := decryptor.pg_decryptor.(*PgHexDecryptor); ok {
		return append(HEX_PREFIX, data...), nil
	} else {
		return data, nil
	}
}

func (decryptor *PgDecryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	// check poison record
	poison_keypair, err := decryptor.key_store.GetPoisonKeyPair()
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't load poison keypair", err))
		return true, err
	} else {
		log.Println("Debug: check on poison record")
		// try decrypt using poison key pair
		_, _, err := decryptor.matched_decryptor.ReadSymmetricKey(poison_keypair.Private, reader)
		if err == nil {
			log.Println("Warning: recognized poison record")
			err := decryptor.GetPoisonCallbackStorage().Call()
			if err != nil {
				log.Printf("Error: unexpected error in poison record callbacks - %v\n", err)
			}
			return true, err
		}
	}
	return false, nil
}

var hex_tag_symbols = hex.EncodeToString([]byte{base.TAG_SYMBOL})
var HEX_SYMBOL byte = byte(hex_tag_symbols[0])

func (decryptor *PgDecryptor) BeginTagIndex(block []byte) (int, int) {
	_, ok := decryptor.pg_decryptor.(*PgHexDecryptor)
	if ok {
		if i := utils.FindTag(HEX_SYMBOL, decryptor.pg_decryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
			decryptor.matched_decryptor = decryptor.pg_decryptor
			return i, decryptor.pg_decryptor.GetTagBeginLength()
		}
	} else {
		// escape format
		if i := utils.FindTag(base.TAG_SYMBOL, decryptor.pg_decryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
			decryptor.matched_decryptor = decryptor.pg_decryptor
			return i, decryptor.pg_decryptor.GetTagBeginLength()
			// binary format
		}
	}
	if i := utils.FindTag(base.TAG_SYMBOL, decryptor.binary_decryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
		decryptor.matched_decryptor = decryptor.binary_decryptor
		return i, decryptor.binary_decryptor.GetTagBeginLength()
	}
	decryptor.matched_decryptor = nil
	return utils.NOT_FOUND, decryptor.GetTagBeginLength()
}

var hex_zone_symbols = hex.EncodeToString([]byte{zone.ZONE_TAG_SYMBOL})
var HEX_ZONE_SYMBOL byte = byte(hex_zone_symbols[0])

func (decryptor *PgDecryptor) MatchZoneInBlock(block []byte) {
	_, ok := decryptor.pg_decryptor.(*PgHexDecryptor)
	if ok {
		slice_copy := block[:]
		for {
			i := utils.FindTag(HEX_ZONE_SYMBOL, HEX_ZONE_TAG_LENGTH, slice_copy)
			if i == utils.NOT_FOUND {
				break
			} else {
				id := make([]byte, zone.ZONE_ID_BLOCK_LENGTH)
				hex_id := slice_copy[i : i+HEX_ZONE_ID_BLOCK_LENGTH]
				hex.Decode(id, hex_id)
				if decryptor.key_store.HasZonePrivateKey(id) {
					decryptor.zone_matcher.SetMatched(id)
					return
				}
				slice_copy = slice_copy[i+1:]
			}
		}
	} else {
		slice_copy := block[:]
		for {
			// escape format
			i := utils.FindTag(zone.ZONE_TAG_SYMBOL, ESCAPE_ZONE_TAG_LENGTH, block)
			if i == utils.NOT_FOUND {
				break
			} else {
				if decryptor.key_store.HasZonePrivateKey(slice_copy[i : i+ESCAPE_ZONE_ID_BLOCK_LENGTH]) {
					decryptor.zone_matcher.SetMatched(slice_copy[i : i+ESCAPE_ZONE_ID_BLOCK_LENGTH])
					return
				}
				slice_copy = slice_copy[i+1:]
			}

		}
	}
	slice_copy := block[:]
	for {
		// binary format
		i := utils.FindTag(zone.ZONE_TAG_SYMBOL, zone.ZONE_TAG_LENGTH, block)
		if i == utils.NOT_FOUND {
			break
		} else {
			if decryptor.key_store.HasZonePrivateKey(slice_copy[i : i+zone.ZONE_ID_BLOCK_LENGTH]) {
				decryptor.zone_matcher.SetMatched(slice_copy[i : i+ESCAPE_ZONE_ID_BLOCK_LENGTH])
				return
			}
			slice_copy = slice_copy[i+1:]
		}
	}
	return
}

func (decryptor *PgDecryptor) GetTagBeginLength() int {
	return decryptor.pg_decryptor.GetTagBeginLength()
}

func (decryptor *PgDecryptor) GetZoneIdLength() int {
	return decryptor.pg_decryptor.GetTagBeginLength()
}
