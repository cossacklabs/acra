/*
Copyright 2016, Cossack Labs Limited

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

// Package base contains AcraStruct decryptor interface and callbacks. Decryptor is database-dependent object:
// PgDecryptor reads data from PostgreSQL databases, finds AcraStructs and decrypt them,
// MySQLDecryptor reads and decrypts AcraStruct from MySQL databases in the similar way,
// BinaryDecryptor doesn't care about database protocol, it finds and decrypts AcraStruct from binary blobs.
package base

import (
	"errors"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"io"
)

// Errors show errors while recognizing of valid AcraStructs.
var (
	ErrFakeAcraStruct = errors.New("fake acra struct")
	ErrPoisonRecord   = errors.New("poison record detected")
)

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

// Constants that setup which symbol would be used at start in AcraStruct to simplify recognizing from other binary data
// Double-quote was chosen because it's printable symbol (help in debugging when we can see in console that it's start of
// AcraStruct) and rarely used sequentially
// Tag length was chosen
const (
	// TagSymbol used in begin tag in AcraStruct
	TagSymbol byte = '"'
)

// TAG_BEGIN represents begin sequence of bytes for AcraStruct.
var TAG_BEGIN = []byte{TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol, TagSymbol}

// Shows key and data length.
const (
	// length of EC public key
	PublicKeyLength = 45
	// length of 32 byte of symmetric key wrapped to smessage
	SMessageKeyLength = 84
	KeyBlockLength    = PublicKeyLength + SMessageKeyLength

	SymmetricKeySize = 32
	// DataLengthSize length of part of AcraStruct that store data part length. So max data size is 2^^64 that
	// may be wrapped into AcraStruct. We decided that 2^^64 is enough and not much as 8 byte overhead per AcraStruct
	DataLengthSize = 8
)

// DataDecryptor describes AcraStruct decryptor.
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

// Decryptor describes all methods needed to find and decrypt AcraStruct in binary file.
type Decryptor interface {
	DataDecryptor
	// register key store that will be used for retrieving private keys
	SetKeyStore(keystore.KeyStore)
	// return private key for current connected client for decrypting symmetric
	// key with secure message
	GetPrivateKey() (*keys.PrivateKey, error)
	TurnOnPoisonRecordCheck(bool)
	IsPoisonRecordCheckOn() bool
	// register storage of callbacks for detected poison records
	SetPoisonCallbackStorage(*PoisonCallbackStorage)
	// get current storage of callbacks for detected poison records
	GetPoisonCallbackStorage() *PoisonCallbackStorage
	SetZoneMatcher(*zone.ZoneIDMatcher)
	GetZoneMatcher() *zone.ZoneIDMatcher
	GetMatchedZoneID() []byte
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

// CheckReadWrite check that n == expectedN and err != nil
func CheckReadWrite(n, expectedN int, err error) error {
	if err != nil {
		return err
	}
	if n != expectedN {
		return fmt.Errorf("incorrect read/write count. %d != %d", n, expectedN)
	}
	return nil
}
