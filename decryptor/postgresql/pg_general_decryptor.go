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
	isWithZone       bool
	isWholeMatch     bool
	keyStore         keystore.KeyStore
	zoneMatcher      *zone.ZoneIdMatcher
	pgDecryptor      base.DataDecryptor
	binaryDecryptor  base.DataDecryptor
	matchedDecryptor base.DataDecryptor

	poisonKey       []byte
	clientId        []byte
	matchBuffer     []byte
	matchIndex      int
	callbackStorage *base.PoisonCallbackStorage
}

func NewPgDecryptor(clientId []byte, decryptor base.DataDecryptor) *PgDecryptor {
	return &PgDecryptor{
		isWithZone:      false,
		pgDecryptor:     decryptor,
		binaryDecryptor: binary.NewBinaryDecryptor(),
		clientId:        clientId,
		// longest tag (escape) + bin
		matchBuffer:  make([]byte, len(ESCAPE_TAG_BEGIN)+len(base.TAG_BEGIN)),
		matchIndex:   0,
		isWholeMatch: true,
	}
}

func (decryptor *PgDecryptor) SetWithZone(b bool) {
	decryptor.isWithZone = b
}

func (decryptor *PgDecryptor) SetZoneMatcher(zoneMatcher *zone.ZoneIdMatcher) {
	decryptor.zoneMatcher = zoneMatcher
}

func (decryptor *PgDecryptor) IsMatchedZone() bool {
	return decryptor.zoneMatcher.IsMatched() && decryptor.keyStore.HasZonePrivateKey(decryptor.zoneMatcher.GetZoneId())
}

func (decryptor *PgDecryptor) MatchZone(b byte) bool {
	return decryptor.zoneMatcher.Match(b)
}

func (decryptor *PgDecryptor) GetMatchedZoneId() []byte {
	if decryptor.IsWithZone() {
		return decryptor.zoneMatcher.GetZoneId()
	}
	return nil
}

func (decryptor *PgDecryptor) ResetZoneMatch() {
	if decryptor.zoneMatcher != nil {
		decryptor.zoneMatcher.Reset()
	}
}

func (decryptor *PgDecryptor) MatchBeginTag(char byte) bool {
	/* should be called two decryptors */
	matched := decryptor.pgDecryptor.MatchBeginTag(char)
	matched = decryptor.binaryDecryptor.MatchBeginTag(char) || matched
	if matched {
		decryptor.matchBuffer[decryptor.matchIndex] = char
		decryptor.matchIndex++
	}
	return matched
}

func (decryptor *PgDecryptor) IsWithZone() bool {
	return decryptor.isWithZone
}

func (decryptor *PgDecryptor) IsMatched() bool {
	// TODO here pg_decryptor has higher priority than binary_decryptor
	// but can be case when begin tag is equal for binary and escape formats
	// in this case may be error in stream mode
	if decryptor.pgDecryptor.IsMatched() {
		log.Println("Debug: matched pg decryptor")
		decryptor.matchedDecryptor = decryptor.pgDecryptor
		return true
	} else if decryptor.binaryDecryptor.IsMatched() {
		log.Println("Debug: matched binary decryptor")
		decryptor.matchedDecryptor = decryptor.binaryDecryptor
		return true
	} else {
		decryptor.matchedDecryptor = nil
		return false
	}
}
func (decryptor *PgDecryptor) Reset() {
	decryptor.matchedDecryptor = nil
	decryptor.binaryDecryptor.Reset()
	decryptor.pgDecryptor.Reset()
	decryptor.matchIndex = 0
}
func (decryptor *PgDecryptor) GetMatched() []byte {
	return decryptor.matchBuffer[:decryptor.matchIndex]
}

func (decryptor *PgDecryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	symmetricKey, rawData, err := decryptor.matchedDecryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		return symmetricKey, rawData, err
	}
	return symmetricKey, rawData, nil
}

func (decryptor *PgDecryptor) ReadData(symmetricKey, zoneId []byte, reader io.Reader) ([]byte, error) {
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
	correctMatchBeginTagLength := len(decryptor.matchedDecryptor.GetMatched())
	// take diff count of matched between two decryptors
	falseBufferedBeginTagLength := decryptor.matchIndex - correctMatchBeginTagLength
	if falseBufferedBeginTagLength > 0 {
		log.Printf("Debug: return with false matched %v bytes\n", falseBufferedBeginTagLength)
		decrypted, err := decryptor.matchedDecryptor.ReadData(symmetricKey, zoneId, reader)
		return append(decryptor.matchBuffer[:falseBufferedBeginTagLength], decrypted...), err
	}
	return decryptor.matchedDecryptor.ReadData(symmetricKey, zoneId, reader)
}

func (decryptor *PgDecryptor) SetKeyStore(store keystore.KeyStore) {
	decryptor.keyStore = store
}

func (decryptor *PgDecryptor) GetPrivateKey() (*keys.PrivateKey, error) {
	if decryptor.IsWithZone() {
		return decryptor.keyStore.GetZonePrivateKey(decryptor.GetMatchedZoneId())
	}
	return decryptor.keyStore.GetServerDecryptionPrivateKey(decryptor.clientId)
}

func (decryptor *PgDecryptor) GetPoisonCallbackStorage() *base.PoisonCallbackStorage {
	return decryptor.callbackStorage
}

func (decryptor *PgDecryptor) SetPoisonCallbackStorage(storage *base.PoisonCallbackStorage) {
	decryptor.callbackStorage = storage
}

func (decryptor *PgDecryptor) IsWholeMatch() bool {
	return decryptor.isWholeMatch
}

func (decryptor *PgDecryptor) SetWholeMatch(value bool) {
	decryptor.isWholeMatch = value
}

func (decryptor *PgDecryptor) MatchZoneBlock(block []byte) {
	if _, ok := decryptor.pgDecryptor.(*PgHexDecryptor); ok && bytes.Equal(block[:2], HEX_PREFIX) {
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
	_, ok := decryptor.pgDecryptor.(*PgHexDecryptor)
	// in hex format can be \x bytes at beginning
	// we need skip them for correct matching begin tag
	n := 0
	if ok && bytes.Equal(block[:2], HEX_PREFIX) {
		block = block[2:]
		for _, c := range block {
			if !decryptor.pgDecryptor.MatchBeginTag(c) {
				return []byte{}, base.ErrFakeAcraStruct
			}
			n++
			if decryptor.pgDecryptor.IsMatched() {
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
	dataBlock, err := decryptor.SkipBeginInBlock(block)
	if err != nil {
		return []byte{}, err
	}

	reader := bytes.NewReader(dataBlock)
	privateKey, err := decryptor.GetPrivateKey()
	if err != nil {
		log.Println("Warning: can't read private key")
		return []byte{}, err
	}
	key, _, err := decryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		log.Printf("Warning: %v\n", utils.ErrorMessage("can't unwrap symmetric key", err))
		return []byte{}, err
	}
	data, err := decryptor.ReadData(key, decryptor.GetMatchedZoneId(), reader)
	if err != nil {
		log.Printf("Warning: %v\n", utils.ErrorMessage("can't decrypt data with unwrapped symmetric key", err))
		return []byte{}, err
	}
	if _, ok := decryptor.pgDecryptor.(*PgHexDecryptor); ok {
		return append(HEX_PREFIX, data...), nil
	}
	return data, nil
}

func (decryptor *PgDecryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	// check poison record
	poisonKeypair, err := decryptor.keyStore.GetPoisonKeyPair()
	if err != nil {
		log.Printf("Error: %v\n", utils.ErrorMessage("can't load poison keypair", err))
		return true, err
	}
	// try decrypt using poison key pair
	_, _, err = decryptor.matchedDecryptor.ReadSymmetricKey(poisonKeypair.Private, reader)
	if err == nil {
		log.Println("Warning: recognized poison record")
		err := decryptor.GetPoisonCallbackStorage().Call()
		if err != nil {
			log.Printf("Error: unexpected error in poison record callbacks - %v\n", err)
		}
		return true, err
	}
	log.Printf("Debug: not recognized poison record. error returned - %v\n", err)
	return false, nil
}

var hexTagSymbols = hex.EncodeToString([]byte{base.TAG_SYMBOL})
var HEX_SYMBOL byte = byte(hexTagSymbols[0])

func (decryptor *PgDecryptor) BeginTagIndex(block []byte) (int, int) {
	_, ok := decryptor.pgDecryptor.(*PgHexDecryptor)
	if ok {
		if i := utils.FindTag(HEX_SYMBOL, decryptor.pgDecryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
			log.Println("Debug: matched pg decryptor")
			decryptor.matchedDecryptor = decryptor.pgDecryptor
			return i, decryptor.pgDecryptor.GetTagBeginLength()
		}
	} else {
		// escape format
		if i := utils.FindTag(base.TAG_SYMBOL, decryptor.pgDecryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
			log.Println("Debug: matched pg decryptor")
			decryptor.matchedDecryptor = decryptor.pgDecryptor
			return i, decryptor.pgDecryptor.GetTagBeginLength()
			// binary format
		}
	}
	if i := utils.FindTag(base.TAG_SYMBOL, decryptor.binaryDecryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
		log.Println("Debug: matched binary decryptor")
		decryptor.matchedDecryptor = decryptor.binaryDecryptor
		return i, decryptor.binaryDecryptor.GetTagBeginLength()
	}
	decryptor.matchedDecryptor = nil
	return utils.NOT_FOUND, decryptor.GetTagBeginLength()
}

var hexZoneSymbols = hex.EncodeToString([]byte{zone.ZONE_TAG_SYMBOL})
var HEX_ZONE_SYMBOL byte = byte(hexZoneSymbols[0])

func (decryptor *PgDecryptor) MatchZoneInBlock(block []byte) {
	_, ok := decryptor.pgDecryptor.(*PgHexDecryptor)
	if ok {
		sliceCopy := block[:]
		for {
			i := utils.FindTag(HEX_ZONE_SYMBOL, HEX_ZONE_TAG_LENGTH, sliceCopy)
			if i == utils.NOT_FOUND {
				break
			} else {
				id := make([]byte, zone.ZONE_ID_BLOCK_LENGTH)
				hexId := sliceCopy[i : i+HEX_ZONE_ID_BLOCK_LENGTH]
				hex.Decode(id, hexId)
				if decryptor.keyStore.HasZonePrivateKey(id) {
					decryptor.zoneMatcher.SetMatched(id)
					return
				}
				sliceCopy = sliceCopy[i+1:]
			}
		}
	} else {
		sliceCopy := block[:]
		for {
			// escape format
			i := utils.FindTag(zone.ZONE_TAG_SYMBOL, ESCAPE_ZONE_TAG_LENGTH, block)
			if i == utils.NOT_FOUND {
				break
			} else {
				if decryptor.keyStore.HasZonePrivateKey(sliceCopy[i : i+ESCAPE_ZONE_ID_BLOCK_LENGTH]) {
					decryptor.zoneMatcher.SetMatched(sliceCopy[i : i+ESCAPE_ZONE_ID_BLOCK_LENGTH])
					return
				}
				sliceCopy = sliceCopy[i+1:]
			}

		}
	}
	sliceCopy := block[:]
	for {
		// binary format
		i := utils.FindTag(zone.ZONE_TAG_SYMBOL, zone.ZONE_TAG_LENGTH, block)
		if i == utils.NOT_FOUND {
			break
		} else {
			if decryptor.keyStore.HasZonePrivateKey(sliceCopy[i : i+zone.ZONE_ID_BLOCK_LENGTH]) {
				decryptor.zoneMatcher.SetMatched(sliceCopy[i : i+ESCAPE_ZONE_ID_BLOCK_LENGTH])
				return
			}
			sliceCopy = sliceCopy[i+1:]
		}
	}
	return
}

func (decryptor *PgDecryptor) GetTagBeginLength() int {
	return decryptor.pgDecryptor.GetTagBeginLength()
}

func (decryptor *PgDecryptor) GetZoneIdLength() int {
	return decryptor.pgDecryptor.GetTagBeginLength()
}
