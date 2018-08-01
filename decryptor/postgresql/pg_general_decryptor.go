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

// Package postgresql contains PgDecryptor reads data from PostgreSQL databases, finds AcraStructs and decrypt them.
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
	"github.com/sirupsen/logrus"
	"io"
)

// PgDecryptor implements particular data decryptor for PostgreSQL binary format
type PgDecryptor struct {
	isWithZone         bool
	isWholeMatch       bool
	keyStore           keystore.KeyStore
	zoneMatcher        *zone.ZoneIDMatcher
	pgDecryptor        base.DataDecryptor
	binaryDecryptor    base.DataDecryptor
	matchedDecryptor   base.DataDecryptor
	checkPoisonRecords bool

	poisonKey       []byte
	clientID        []byte
	matchBuffer     []byte
	matchIndex      int
	callbackStorage *base.PoisonCallbackStorage
	logger          *logrus.Entry
}

// NewPgDecryptor returns new PgDecryptor hiding inner HEX decryptor or ESCAPE decryptor
// by default checks poison recods and uses WholeMatch mode without zones
func NewPgDecryptor(clientID []byte, decryptor base.DataDecryptor) *PgDecryptor {
	return &PgDecryptor{
		isWithZone:      false,
		pgDecryptor:     decryptor,
		binaryDecryptor: binary.NewBinaryDecryptor(),
		clientID:        clientID,
		// longest tag (escape) + bin
		matchBuffer:        make([]byte, len(ESCAPE_TAG_BEGIN)+len(base.TAG_BEGIN)),
		matchIndex:         0,
		isWholeMatch:       true,
		logger:             logrus.WithField("client_id", string(clientID)),
		checkPoisonRecords: true,
	}
}

// SetWithZone enables or disables decrypting with ZoneID
func (decryptor *PgDecryptor) SetWithZone(b bool) {
	decryptor.isWithZone = b
}

// SetZoneMatcher sets ZoneID matcher
func (decryptor *PgDecryptor) SetZoneMatcher(zoneMatcher *zone.ZoneIDMatcher) {
	decryptor.zoneMatcher = zoneMatcher
}

// GetZoneMatcher returns ZoneID matcher
func (decryptor *PgDecryptor) GetZoneMatcher() *zone.ZoneIDMatcher {
	return decryptor.zoneMatcher
}

// IsMatchedZone returns true if keystore has ZonePrivate key and is AcraStruct has ZoneID header
func (decryptor *PgDecryptor) IsMatchedZone() bool {
	return decryptor.zoneMatcher.IsMatched() && decryptor.keyStore.HasZonePrivateKey(decryptor.zoneMatcher.GetZoneID())
}

// MatchZone returns true if zoneID found inside b bytes
func (decryptor *PgDecryptor) MatchZone(b byte) bool {
	return decryptor.zoneMatcher.Match(b)
}

// GetMatchedZoneID returns ZoneID from AcraStruct
func (decryptor *PgDecryptor) GetMatchedZoneID() []byte {
	if decryptor.IsWithZone() {
		return decryptor.zoneMatcher.GetZoneID()
	}
	return nil
}

// ResetZoneMatch resets zone matcher
func (decryptor *PgDecryptor) ResetZoneMatch() {
	if decryptor.zoneMatcher != nil {
		decryptor.zoneMatcher.Reset()
	}
}

// MatchBeginTag returns true if PgDecryptor and Binary decryptor found BeginTag
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

// IsWithZone returns true if Zone mode is enabled
func (decryptor *PgDecryptor) IsWithZone() bool {
	return decryptor.isWithZone
}

// IsMatched find Begin tag and maps it to Matcher (either PgDecryptor or BinaryDecryptor)
// returns false if can't find tag or can't find corresponded decryptor
func (decryptor *PgDecryptor) IsMatched() bool {
	// TODO here pg_decryptor has higher priority than binary_decryptor
	// but can be case when begin tag is equal for binary and escape formats
	// in this case may be error in stream mode
	if decryptor.pgDecryptor.IsMatched() {
		decryptor.logger.Debugln("Matched pg decryptor")
		decryptor.matchedDecryptor = decryptor.pgDecryptor
		return true
	} else if decryptor.binaryDecryptor.IsMatched() {
		decryptor.logger.Debugln("Matched binary decryptor")
		decryptor.matchedDecryptor = decryptor.binaryDecryptor
		return true
	} else {
		decryptor.matchedDecryptor = nil
		return false
	}
}

// Reset resets both PgDecryptor and BinaryDecryptor and clears matching index
func (decryptor *PgDecryptor) Reset() {
	decryptor.matchedDecryptor = nil
	decryptor.binaryDecryptor.Reset()
	decryptor.pgDecryptor.Reset()
	decryptor.matchIndex = 0
}

// GetMatched returns all matched begin tag bytes
func (decryptor *PgDecryptor) GetMatched() []byte {
	return decryptor.matchBuffer[:decryptor.matchIndex]
}

// ReadSymmetricKey reads, decodes from database format block of data, decrypts symmetric key from
// AcraStruct using Secure message
// returns decrypted symmetric key or ErrFakeAcraStruct error if can't decrypt
func (decryptor *PgDecryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	symmetricKey, rawData, err := decryptor.matchedDecryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		return symmetricKey, rawData, err
	}
	return symmetricKey, rawData, nil
}

// ReadData returns plaintext data, decrypting using SecureCell with ZoneID and symmetricKey
func (decryptor *PgDecryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
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
		decryptor.logger.Debugf("Return with false matched %v bytes", falseBufferedBeginTagLength)
		decrypted, err := decryptor.matchedDecryptor.ReadData(symmetricKey, zoneID, reader)
		return append(decryptor.matchBuffer[:falseBufferedBeginTagLength], decrypted...), err
	}
	// add zone_id to log if it used
	var tempLogger *logrus.Entry
	if decryptor.GetMatchedZoneID() != nil {
		tempLogger = decryptor.logger.WithField("zone_id", string(decryptor.GetMatchedZoneID()))
	} else {
		tempLogger = decryptor.logger
	}

	decrypted, err := decryptor.matchedDecryptor.ReadData(symmetricKey, zoneID, reader)
	if err == nil {
		tempLogger.Infof("Decrypted AcraStruct")
	}
	return decrypted, err
}

// SetKeyStore sets keystore
func (decryptor *PgDecryptor) SetKeyStore(store keystore.KeyStore) {
	decryptor.keyStore = store
}

// GetPrivateKey returns either ZonePrivate key (if Zone mode enabled) or
// Server Decryption private key otherwise
func (decryptor *PgDecryptor) GetPrivateKey() (*keys.PrivateKey, error) {
	if decryptor.IsWithZone() {
		return decryptor.keyStore.GetZonePrivateKey(decryptor.GetMatchedZoneID())
	}
	return decryptor.keyStore.GetServerDecryptionPrivateKey(decryptor.clientID)
}

// TurnOnPoisonRecordCheck turns on or off poison recods check
func (decryptor *PgDecryptor) TurnOnPoisonRecordCheck(val bool) {
	decryptor.logger.Debugf("Set poison record check: %v", val)
	decryptor.checkPoisonRecords = val
}

// IsPoisonRecordCheckOn returns true if poison record check is enabled
func (decryptor *PgDecryptor) IsPoisonRecordCheckOn() bool {
	return decryptor.checkPoisonRecords
}

// GetPoisonCallbackStorage returns storage of poison record callbacks,
// creates new one if no storage set
func (decryptor *PgDecryptor) GetPoisonCallbackStorage() *base.PoisonCallbackStorage {
	if decryptor.callbackStorage == nil {
		decryptor.callbackStorage = base.NewPoisonCallbackStorage()
	}
	return decryptor.callbackStorage
}

// SetPoisonCallbackStorage sets storage of poison record callbacks
func (decryptor *PgDecryptor) SetPoisonCallbackStorage(storage *base.PoisonCallbackStorage) {
	decryptor.callbackStorage = storage
}

// IsWholeMatch returns if AcraStruct sits in the whole database cell
func (decryptor *PgDecryptor) IsWholeMatch() bool {
	return decryptor.isWholeMatch
}

// SetWholeMatch sets isWholeMatch
func (decryptor *PgDecryptor) SetWholeMatch(value bool) {
	decryptor.isWholeMatch = value
}

// MatchZoneBlock returns zone data
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

// HEX_PREFIX represents \x bytes at beginning of HEX byte format
var HEX_PREFIX = []byte{'\\', 'x'}

// SkipBeginInBlock returns bytes without BeginTag
// or ErrFakeAcraStruct otherwise
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

// DecryptBlock returns plaintext content of AcraStruct decrypted by correct PgDecryptor,
// handles all settings (if AcraStruct has Zone, if keys can be read etc)
// appends HEX Prefix for Hex bytes mode
func (decryptor *PgDecryptor) DecryptBlock(block []byte) ([]byte, error) {
	dataBlock, err := decryptor.SkipBeginInBlock(block)
	if err != nil {
		return []byte{}, err
	}

	reader := bytes.NewReader(dataBlock)
	privateKey, err := decryptor.GetPrivateKey()
	if err != nil {
		decryptor.logger.Warningln("Can't read private key")
		return []byte{}, err
	}
	key, _, err := decryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		decryptor.logger.Warningf("%v", utils.ErrorMessage("Can't unwrap symmetric key", err))
		return []byte{}, err
	}
	data, err := decryptor.ReadData(key, decryptor.GetMatchedZoneID(), reader)
	if err != nil {
		decryptor.logger.Warningf("%v", utils.ErrorMessage("Can't decrypt data with unwrapped symmetric key", err))
		return []byte{}, err
	}
	if _, ok := decryptor.pgDecryptor.(*PgHexDecryptor); ok {
		return append(HEX_PREFIX, data...), nil
	}
	return data, nil
}

// CheckPoisonRecord tries to decrypt AcraStruct using Poison records keys
// if decryption is successful, executes poison record callbacks
// returns true and no error if poison record found
// returns error otherwise
func (decryptor *PgDecryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	// check poison record
	poisonKeypair, err := decryptor.keyStore.GetPoisonKeyPair()
	if err != nil {
		decryptor.logger.WithError(err).Errorln("Can't load poison keypair")
		return true, err
	}
	// try decrypt using poison key pair
	_, _, err = decryptor.matchedDecryptor.ReadSymmetricKey(poisonKeypair.Private, reader)
	if err == nil {
		decryptor.logger.Warningln("Recognized poison record")
		if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
			err := decryptor.GetPoisonCallbackStorage().Call()
			if err != nil {
				decryptor.logger.WithError(err).Errorln("Unexpected error in poison record callbacks")
			}
		}
		return true, nil
	}
	decryptor.logger.Debugf("Not recognized poison record. error returned - %v", err)
	return false, nil
}

var hexTagSymbols = hex.EncodeToString([]byte{base.TAG_SYMBOL})

// HEX_SYMBOL is HEX representation of TAG_SYMBOL
var HEX_SYMBOL = byte(hexTagSymbols[0])

// BeginTagIndex returns tag start index and length of tag (depends on decryptor type)
func (decryptor *PgDecryptor) BeginTagIndex(block []byte) (int, int) {
	_, ok := decryptor.pgDecryptor.(*PgHexDecryptor)
	if ok {
		if i := utils.FindTag(HEX_SYMBOL, decryptor.pgDecryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
			decryptor.logger.Debugln("Matched pg decryptor")
			decryptor.matchedDecryptor = decryptor.pgDecryptor
			return i, decryptor.pgDecryptor.GetTagBeginLength()
		}
	} else {
		// escape format
		if i := utils.FindTag(base.TAG_SYMBOL, decryptor.pgDecryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
			decryptor.logger.Debugln("Matched pg decryptor")
			decryptor.matchedDecryptor = decryptor.pgDecryptor
			return i, decryptor.pgDecryptor.GetTagBeginLength()
			// binary format
		}
	}
	if i := utils.FindTag(base.TAG_SYMBOL, decryptor.binaryDecryptor.GetTagBeginLength(), block); i != utils.NOT_FOUND {
		decryptor.logger.Debugln("Matched binary decryptor")
		decryptor.matchedDecryptor = decryptor.binaryDecryptor
		return i, decryptor.binaryDecryptor.GetTagBeginLength()
	}
	decryptor.matchedDecryptor = nil
	return utils.NOT_FOUND, decryptor.GetTagBeginLength()
}

var hexZoneSymbols = hex.EncodeToString([]byte{zone.ZONE_TAG_SYMBOL})

// HEX_ZONE_SYMBOL is HEX representation of ZONE_TAG_SYMBOL
var HEX_ZONE_SYMBOL = byte(hexZoneSymbols[0])

// MatchZoneInBlock finds ZoneId in AcraStruct and marks decryptor matched
// (depends on decryptor type)
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
				hexID := sliceCopy[i : i+HEX_ZONE_ID_BLOCK_LENGTH]
				hex.Decode(id, hexID)
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

// GetTagBeginLength returns begin tag length, depends on decryptor type
func (decryptor *PgDecryptor) GetTagBeginLength() int {
	return decryptor.pgDecryptor.GetTagBeginLength()
}

// GetZoneIDLength returns begin tag length, depends on decryptor type
func (decryptor *PgDecryptor) GetZoneIDLength() int {
	return decryptor.pgDecryptor.GetTagBeginLength()
}
