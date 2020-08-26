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

package postgresql

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"os"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/binary"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

var errPlainData = errors.New("plain data without AcraStruct signature")

// PgDecryptor implements particular data decryptor for PostgreSQL binary format
type PgDecryptor struct {
	isWithZone         bool
	isWholeMatch       bool
	keyStore           keystore.DecryptionKeyStore
	zoneMatcher        *zone.Matcher
	binaryDecryptor    base.DataDecryptor
	checkPoisonRecords bool

	clientID             []byte
	matchBuffer          []byte
	matchIndex           int
	callbackStorage      *base.PoisonCallbackStorage
	logger               *log.Entry
	dataProcessor        base.DataProcessor
	dataProcessorContext *base.DataProcessorContext
}

// NewPgDecryptor returns new PgDecryptor hiding inner HEX decryptor or ESCAPE decryptor
// by default checks poison recods and uses WholeMatch mode without zones
func NewPgDecryptor(clientID []byte, decryptor base.DataDecryptor, withZone bool, keystore keystore.DecryptionKeyStore) *PgDecryptor {
	logger := log.WithField("client_id", string(clientID))
	decryptor.SetLogger(logger)
	return &PgDecryptor{
		isWithZone:      withZone,
		binaryDecryptor: binary.NewBinaryDecryptor(logger),
		clientID:        clientID,
		// longest tag (escape) + bin
		matchBuffer:          make([]byte, len(EscapeTagBegin)+len(base.TagBegin)),
		matchIndex:           0,
		isWholeMatch:         true,
		logger:               logger,
		checkPoisonRecords:   true,
		keyStore:             keystore,
		dataProcessorContext: base.NewDataProcessorContext(clientID, withZone, keystore).UseContext(logging.SetLoggerToContext(context.Background(), logger)),
	}
}

// SetLogger set logger
func (decryptor *PgDecryptor) SetLogger(logger *log.Entry) {
	decryptor.binaryDecryptor.SetLogger(logger)
}

// SetWithZone enables or disables decrypting with ZoneID
func (decryptor *PgDecryptor) SetWithZone(b bool) {
	decryptor.isWithZone = b
}

// SetZoneMatcher sets ZoneID matcher
func (decryptor *PgDecryptor) SetZoneMatcher(zoneMatcher *zone.Matcher) {
	decryptor.zoneMatcher = zoneMatcher
}

// GetZoneMatcher returns ZoneID matcher
func (decryptor *PgDecryptor) GetZoneMatcher() *zone.Matcher {
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
	matched := decryptor.binaryDecryptor.MatchBeginTag(char)
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

// IsMatched find Begin tag and maps it to Matcher (either PgDecryptor or Decryptor)
// returns false if can't find tag or can't find corresponded decryptor
func (decryptor *PgDecryptor) IsMatched() bool {
	return decryptor.binaryDecryptor.IsMatched()
}

// Reset resets both PgDecryptor and Decryptor and clears matching index
func (decryptor *PgDecryptor) Reset() {
	decryptor.binaryDecryptor.Reset()
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
	symmetricKey, rawData, err := decryptor.binaryDecryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		return symmetricKey, rawData, err
	}
	return symmetricKey, rawData, nil
}

// ReadSymmetricKeyRotated reads, decodes from database format block of data, decrypts symmetric key from
// AcraStruct using Secure message
// returns decrypted symmetric key or ErrFakeAcraStruct error if can't decrypt
func (decryptor *PgDecryptor) ReadSymmetricKeyRotated(privateKeys []*keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	symmetricKey, rawData, err := decryptor.binaryDecryptor.ReadSymmetricKeyRotated(privateKeys, reader)
	if err != nil {
		return symmetricKey, rawData, err
	}
	return symmetricKey, rawData, nil
}

// ReadData returns plaintext data, decrypting using SecureCell with ZoneID and symmetricKey
func (decryptor *PgDecryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
	/* due to using two decryptors can be case when one decryptor match 2 bytes
	from TagBegin then didn't match anymore but another decryptor matched at
	this time and was successfully used for decryption, we need return 2 bytes
	matched and buffered by first decryptor and decrypted data from the second

	for example case of matching begin tag:
	BEGIN_TA - failed decryptor1
	00BEGIN_TAG - successful decryptor2
	in this case first decryptor1 matched not full begin_tag and failed on 'G' but
	at this time was matched decryptor2 and successfully matched next bytes and decrypted data
	so we need return diff of two matches 'BE' and decrypted data
	*/

	// add zone_id to log if it used
	logger := log.NewEntry(decryptor.logger.Logger)
	if decryptor.GetMatchedZoneID() != nil {
		logger = decryptor.logger.WithField("zone_id", string(decryptor.GetMatchedZoneID()))
		// use temporary logger in matched decryptor
		decryptor.binaryDecryptor.SetLogger(logger)
		// reset to default logger without zone_id
		defer decryptor.binaryDecryptor.SetLogger(decryptor.logger)
	}

	// take length of fully matched tag begin (each decryptor match tag begin with different length)
	correctMatchBeginTagLength := len(decryptor.binaryDecryptor.GetMatched())
	// take diff count of matched between two decryptors
	falseBufferedBeginTagLength := decryptor.matchIndex - correctMatchBeginTagLength
	if falseBufferedBeginTagLength > 0 {
		logger.Debugf("Return with false matched %v bytes", falseBufferedBeginTagLength)
		decrypted, err := decryptor.binaryDecryptor.ReadData(symmetricKey, zoneID, reader)
		if err != nil {
			return nil, err
		}
		logger.Debugln("Decrypted AcraStruct")
		return append(decryptor.matchBuffer[:falseBufferedBeginTagLength], decrypted...), nil
	}

	decrypted, err := decryptor.binaryDecryptor.ReadData(symmetricKey, zoneID, reader)
	if err != nil {
		return nil, err
	}
	logger.Debugln("Decrypted AcraStruct")
	return decrypted, nil
}

// SetKeyStore sets keystore
func (decryptor *PgDecryptor) SetKeyStore(store keystore.DecryptionKeyStore) {
	decryptor.keyStore = store
}

// GetPrivateKey returns private key for decrypting AcraStructs.
// This is either ZonePrivate key (if Zone mode enabled)
// or Server Decryption private key otherwise.
func (decryptor *PgDecryptor) GetPrivateKey() (*keys.PrivateKey, error) {
	if decryptor.IsWithZone() {
		return decryptor.keyStore.GetZonePrivateKey(decryptor.GetMatchedZoneID())
	}
	return decryptor.keyStore.GetServerDecryptionPrivateKey(decryptor.clientID)
}

// GetPrivateKeys returns private keys for decrypting AcraStructs.
// These are either ZonePrivate keys (if Zone mode enabled)
// or Server Decryption private key otherwise.
func (decryptor *PgDecryptor) GetPrivateKeys() ([]*keys.PrivateKey, error) {
	if decryptor.IsWithZone() {
		return decryptor.keyStore.GetZonePrivateKeys(decryptor.GetMatchedZoneID())
	}
	return decryptor.keyStore.GetServerDecryptionPrivateKeys(decryptor.clientID)
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
	if logging.IsDebugLevel(decryptor.logger) {
		if value {
			decryptor.logger = decryptor.logger.WithField("decrypt_mode", base.DecryptWhole)
		}
		decryptor.logger = decryptor.logger.WithField("decrypt_mode", base.DecryptInline)
	}
}

// MatchZoneBlock returns zone data
func (decryptor *PgDecryptor) MatchZoneBlock(block []byte) {
	for _, c := range block {
		if !decryptor.MatchZone(c) {
			return
		}
	}
}

// HexPrefix represents \x bytes at beginning of HEX byte format
var HexPrefix = []byte{'\\', 'x'}

// SkipBeginInBlock returns bytes without BeginTag
// or ErrFakeAcraStruct otherwise
func (decryptor *PgDecryptor) SkipBeginInBlock(block []byte) ([]byte, error) {
	// in hex format can be \x bytes at beginning
	// we need skip them for correct matching begin tag
	n := 0

	for _, c := range block {
		if !decryptor.MatchBeginTag(c) {
			return []byte{}, base.ErrFakeAcraStruct
		}
		n++
		if decryptor.IsMatched() {
			break
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
	ctx := decryptor.dataProcessorContext.UseZoneID(decryptor.GetMatchedZoneID())
	ctx.WithZone = decryptor.IsWithZone()
	decrypted, err := decryptor.dataProcessor.Process(block, ctx)
	if err == nil {
		return decrypted, nil
	}
	// avoid logging errors when block is not AcraStruct
	if err == base.ErrIncorrectAcraStructTagBegin {
		return nil, errPlainData
	} else if err == base.ErrIncorrectAcraStructLength {
		return nil, errPlainData
	}
	return nil, err
}

// CheckPoisonRecord tries to decrypt AcraStruct using Poison records keys
// if decryption is successful, executes poison record callbacks
// returns true and no error if poison record found
// returns error otherwise
func (decryptor *PgDecryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	if !decryptor.IsPoisonRecordCheckOn() {
		return false, nil
	}
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return false, err
	}

	// check poison record
	poisonKeypair, err := decryptor.keyStore.GetPoisonKeyPair()
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).WithError(err).Errorln("Can't load poison keypair")
		return true, err
	}

	_, err = base.DecryptAcrastruct(data, poisonKeypair.Private, nil)
	if err == nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Warningln("Recognized poison record")
		if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
			err = decryptor.GetPoisonCallbackStorage().Call()
			if err != nil {
				decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Unexpected error in poison record callbacks")
			}
			decryptor.logger.Debugln("Processed all callbacks on poison record")
		}
		return true, nil
	}
	decryptor.logger.WithField("data", string(data[:10])).WithError(err).Errorln("Didn't decrypt poison record")
	return false, nil
}

var hexTagSymbols = hex.EncodeToString([]byte{base.TagSymbol})

// HexSymbol is HEX representation of TagSymbol
var HexSymbol = byte(hexTagSymbols[0])

// BeginTagIndex returns tag start index and length of tag (depends on decryptor type)
func (decryptor *PgDecryptor) BeginTagIndex(block []byte) (int, int) {
	if i := bytes.Index(block, base.TagBegin); i != utils.NotFound {
		decryptor.logger.Debugln("Matched binary decryptor")
		return i, decryptor.binaryDecryptor.GetTagBeginLength()
	}
	return utils.NotFound, decryptor.GetTagBeginLength()
}

var hexZoneSymbols = hex.EncodeToString([]byte{zone.ZoneTagSymbol})

// HexZoneSymbol is HEX representation of ZoneTagSymbol
var HexZoneSymbol = byte(hexZoneSymbols[0])

// MatchZoneInBlock finds ZoneId in AcraStruct and marks decryptor matched
// (depends on decryptor type)
func (decryptor *PgDecryptor) MatchZoneInBlock(block []byte) {
	sliceCopy := block[:]
	for {
		// binary format
		i := bytes.Index(block, zone.ZoneIDBegin)
		if i == utils.NotFound {
			break
		} else {
			if decryptor.keyStore.HasZonePrivateKey(sliceCopy[i : i+zone.ZoneIDBlockLength]) {
				decryptor.zoneMatcher.SetMatched(sliceCopy[i : i+EscapeZoneIDBlockLength])
				return
			}
			sliceCopy = sliceCopy[i+1:]
		}
	}
	return
}

// GetTagBeginLength returns begin tag length, depends on decryptor type
func (decryptor *PgDecryptor) GetTagBeginLength() int {
	return decryptor.binaryDecryptor.GetTagBeginLength()
}

// GetZoneIDLength returns begin tag length, depends on decryptor type
func (decryptor *PgDecryptor) GetZoneIDLength() int {
	return decryptor.binaryDecryptor.GetTagBeginLength()
}

// SetDataProcessor replace current with new processor
func (decryptor *PgDecryptor) SetDataProcessor(processor base.DataProcessor) {
	decryptor.dataProcessor = processor
}

// ID returns decryption subscriber identification.
func (decryptor *PgDecryptor) ID() string {
	return "PgDecryptor"
}

// OnColumn handler which process column data on db response and try to decrypt/detect poison record
func (decryptor *PgDecryptor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	span := trace.FromContext(ctx)
	// try to skip small piece of data that can't be valuable for us
	// in zonemode skip data which less then zoneid length
	// without zonemode check that data has length more than min AcraStruct length
	if (decryptor.IsWithZone() && len(data) < zone.ZoneIDBlockLength) || (!decryptor.IsWithZone() && len(data) < base.GetMinAcraStructLength()) {
		logger.WithFields(log.Fields{"lest": len(data) < zone.ZoneIDBlockLength, "zone_length": zone.ZoneIDBlockLength, "length": len(data), "with_zone": decryptor.IsWithZone()}).Debugln("Skip decryption because length of block too small for ZoneId or AcraStruct")
		return ctx, data, nil
	}
	decryptor.Reset()
	span.AddAttributes(trace.BoolAttribute("decryption", true))

	// Zone anyway should be passed as whole block
	// so try to match before any operations if we process with ZoneMode on
	if base.NeedMatchZone(decryptor) {
		span.AddAttributes(trace.BoolAttribute("match_zone", true))
		// try to match zone
		decryptor.MatchZoneBlock(data)
		var err error
		if decryptor.IsWholeMatch() {
			// check that it's not poison record
			err = checkWholePoisonRecord(data, decryptor, logger)
		} else {
			// check that it's not poison record
			err = checkInlinePoisonRecordInBlock(data, decryptor, logger)
		}
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check poison record in block")
			return ctx, nil, err
		}
	}

	// create temporary logger to log related zone_id in flow of decryption
	// client_id set on higher level on start of processing connection
	decryptionLogger := logger.WithField("zone_id", string(decryptor.GetMatchedZoneID()))
	var newData []byte
	var err error
	if decryptor.IsWholeMatch() {
		newData, err = decryptor.processWholeBlockDecryption(ctx, data, decryptionLogger)
		if err != nil {
			decryptionLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Errorln("Can't process whole block")
			return ctx, nil, err
		}
		return ctx, newData, err
	}
	// else "injected cell mode", inline acrastruct
	newData, err = decryptor.processInlineBlockDecryption(ctx, data, decryptionLogger)
	if err != nil {
		decryptionLogger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Errorln("Can't process block with inline mode")
		return ctx, nil, err
	}

	decryptor.Reset()
	// reset matched zone only if was successful decryption
	if len(data) != len(newData) {
		if os.Getenv("ZONE_FOR_ROW") != "on" {
			decryptor.ResetZoneMatch()
		}
	}
	return ctx, newData, nil
}

// processWholeBlockDecryption try to decrypt data of column as whole AcraStruct and replace with decrypted data on success
func (decryptor *PgDecryptor) processWholeBlockDecryption(ctx context.Context, data []byte, logger *log.Entry) ([]byte, error) {
	span := trace.FromContext(ctx)
	decryptor.Reset()
	// TODO here we replace context with correct logger with new passed from caller
	decryptor.dataProcessorContext.UseContext(ctx)
	decrypted, err := decryptor.DecryptBlock(data)
	if err == errPlainData {
		// it's not AcraStruct
		return data, nil
	}
	if err != nil {
		span.AddAttributes(trace.BoolAttribute("failed_decryption", true))
		// check poison records on failed decryption
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt AcraStruct: can't unwrap symmetric key")
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		if decryptor.IsPoisonRecordCheckOn() {
			decryptor.Reset()
			if err := checkWholePoisonRecord(data, decryptor, logger); err != nil {
				return nil, err
			}
		}
		return data, nil
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	return decrypted, nil
}

func (decryptor *PgDecryptor) processInlineBlockDecryption(ctx context.Context, data []byte, logger *log.Entry) ([]byte, error) {
	span := trace.FromContext(ctx)
	// inline mode
	currentIndex := 0
	outputBlock := bytes.NewBuffer(make([]byte, 0, len(data)))
	hasDecryptedData := false
	for {
		// search AcraStruct's begin tags through all block of data and try to decrypt
		beginTagIndex, _ := decryptor.BeginTagIndex(data[currentIndex:])
		if beginTagIndex == utils.NotFound {
			outputBlock.Write(data[currentIndex:])
			// no AcraStructs in column decryptedData
			break
		}
		// convert to absolute index
		beginTagIndex += currentIndex
		// write data before start of AcraStruct
		outputBlock.Write(data[currentIndex:beginTagIndex])
		currentIndex = beginTagIndex

		if len(data[currentIndex:]) > base.GetMinAcraStructLength() {
			acrastructLength := base.GetDataLengthFromAcraStruct(data[currentIndex:]) + base.GetMinAcraStructLength()
			if acrastructLength > 0 && acrastructLength <= len(data[currentIndex:]) {
				endIndex := currentIndex + acrastructLength
				// TODO here we replace context with correct logger with new passed from caller
				decryptor.dataProcessorContext.UseContext(ctx)
				decryptedData, err := decryptor.DecryptBlock(data[currentIndex:endIndex])
				if err != nil {
					if decryptor.IsPoisonRecordCheckOn() {
						logger.Infoln("Check poison records")
						blockReader := bytes.NewReader(data[currentIndex:endIndex])
						poisoned, err := decryptor.CheckPoisonRecord(blockReader)
						if err = handlePoisonCheckResult(decryptor, poisoned, err, logger); err != nil {
							return nil, err
						}
					}
					span.AddAttributes(trace.BoolAttribute("failed_decryption", true))
					base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
					logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt AcraStruct: can't decrypt data with unwrapped symmetric key")
					// write current read byte to not process him in next iteration
					outputBlock.Write([]byte{data[currentIndex]})
					currentIndex++
					continue
				}
				logger.Infoln("Decrypted AcraStruct")
				base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
				outputBlock.Write(decryptedData)
				currentIndex += acrastructLength
				hasDecryptedData = true
				continue
			}
		}
		// write current read byte to not process him in next iteration
		outputBlock.Write([]byte{data[currentIndex]})
		currentIndex++
		continue
	}
	if hasDecryptedData {
		logger.WithFields(log.Fields{"old_size": len(data), "new_size": outputBlock.Len()}).Debugln("Result was changed")
		if os.Getenv("ZONE_FOR_ROW") != "on" {
			decryptor.ResetZoneMatch()
		}
		decryptor.Reset()
		return outputBlock.Bytes(), nil
	}
	logger.Debugln("Result was not changed")
	return data, nil
}
