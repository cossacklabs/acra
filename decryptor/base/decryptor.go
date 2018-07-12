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
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io"
)

// error show that failed acra struct recognizing but data is may be valid
var ErrFakeAcraStruct = errors.New("fake acra struct")
var ErrPoisonRecord = errors.New("poison record detected")

/*
which symbols can be used - 2 3 4 5 6 7
hex   char dec  bin
'22' - " - 34 - 0b100010
'33' - 3 - 51 - 0b110011
'44' - D - 68 - 0b1000100
'55' - U - 85 - 0b1010101
'66' - f - 102 - 0b1100110
'77' - w - 119 - 0b1110111
<"> decided as less possible occurrence in sequence as 8 bytes in a row
*/

//var TAG_BEGIN = []byte{133, 32, 251}
const (
	TAG_SYMBOL byte = '"'
)

var TAG_BEGIN = []byte{TAG_SYMBOL, TAG_SYMBOL, TAG_SYMBOL, TAG_SYMBOL, TAG_SYMBOL, TAG_SYMBOL, TAG_SYMBOL, TAG_SYMBOL}

const (
	// length of EC public key
	PUBLIC_KEY_LENGTH = 45
	// length of 32 byte of symmetric key wrapped to smessage
	SMESSAGE_KEY_LENGTH = 84
	KEY_BLOCK_LENGTH    = PUBLIC_KEY_LENGTH + SMESSAGE_KEY_LENGTH

	SYMMETRIC_KEY_SIZE = 32
	DATA_LENGTH_SIZE   = 8
)

// getDataLengthFromAcraStruct unpack data length value from AcraStruct
func getDataLengthFromAcraStruct(data []byte) int {
	dataLengthBlock := data[GetMinAcraStructLength()-DATA_LENGTH_SIZE : GetMinAcraStructLength()]
	return int(binary.LittleEndian.Uint64(dataLengthBlock))
}

// getMinAcraStructLength return minimal length of AcraStruct
// because in golang we can't declare byte array as constant we need to calculate length of TAG_BEGIN in runtime
// or hardcode as constant and maintain len(TAG_BEGIN) == CONST_VALUE
func GetMinAcraStructLength() int {
	return len(TAG_BEGIN) + KEY_BLOCK_LENGTH + DATA_LENGTH_SIZE
}

var ErrIncorrectAcraStructLength = errors.New("AcraStruct has incorrect length")
var ErrIncorrectAcraStructDataLength = errors.New("AcraStruct has incorrect data length value")

// ValidateAcraStructLength check that data has minimal length for AcraStruct and data block equal to data length in AcraStruct
func ValidateAcraStructLength(data []byte) error {
	baseLength := GetMinAcraStructLength()
	if len(data) < baseLength {
		return ErrIncorrectAcraStructLength
	}
	dataLength := getDataLengthFromAcraStruct(data)
	if dataLength != len(data[GetMinAcraStructLength():]) {
		return ErrIncorrectAcraStructDataLength
	}
	return nil
}

type DataDecryptor interface {
	// try match begin tag per byte
	MatchBeginTag(byte) bool
	// return true if all bytes from begin tag matched by MatchBeginTag
	IsMatched() bool
	// reset state of matching begin tag
	Reset()
	// return all matched begin tag bytes
	GetMatched() []byte
	// read, decode from db format block of data, decrypt symmetric key from
	// acrastruct using secure message
	// return decrypted data or data as is if fail
	// db specific
	ReadSymmetricKey(*keys.PrivateKey, io.Reader) ([]byte, []byte, error)
	// read and decrypt data or return as is if fail
	// db specific
	ReadData([]byte, []byte, io.Reader) ([]byte, error)
	GetTagBeginLength() int
}

type Decryptor interface {
	DataDecryptor
	// register key store that will be used for retrieving private keys
	SetKeyStore(keystore.KeyStore)
	// return private key for current connected client for decrypting symmetric
	// key with secure message
	GetPrivateKey() (*keys.PrivateKey, error)
	// register storage of callbacks for detected poison records
	SetPoisonCallbackStorage(*PoisonCallbackStorage)
	// get current storage of callbacks for detected poison records
	GetPoisonCallbackStorage() *PoisonCallbackStorage
	SetZoneMatcher(*zone.ZoneIdMatcher)
	GetZoneMatcher() *zone.ZoneIdMatcher
	GetMatchedZoneId() []byte
	MatchZone(byte) bool
	IsWithZone() bool
	SetWithZone(bool)
	IsMatchedZone() bool
	ResetZoneMatch()
	IsWholeMatch() bool
	SetWholeMatch(bool)
	DecryptBlock([]byte) ([]byte, error)
	SkipBeginInBlock(block []byte) ([]byte, error)
	MatchZoneBlock([]byte)
	CheckPoisonRecord(reader io.Reader) (bool, error)
	// return tag start index and length of tag (depends on decryptor type)
	BeginTagIndex([]byte) (int, int)
	MatchZoneInBlock([]byte)
}

func CheckReadWrite(n, expectedN int, err error, errCh chan<- error) bool {
	if err != nil {
		errCh <- err
		return false
	}
	if n != expectedN {
		errCh <- fmt.Errorf("incorrect read/write count. %d != %d", n, expectedN)
		return false
	}
	return true
}
