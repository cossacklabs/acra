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

// Package mysql contains Decryptor that reads data from MySQL database, finds AcraStructs and decrypt them.
package mysql

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/binary"
	"github.com/cossacklabs/acra/decryptor/postgresql"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	log "github.com/sirupsen/logrus"
)

type decryptFunc func([]byte) ([]byte, error)

var errPlainData = errors.New("plain data without AcraStruct signature")

// Decryptor used to decrypt AcraStruct from MySQL fields
type Decryptor struct {
	base.Decryptor
	binaryDecryptor      *binary.Decryptor
	keyStore             keystore.KeyStore
	decryptFunc          decryptFunc
	log                  *log.Entry
	clientID             []byte
	dataProcessor        base.DataProcessor
	dataProcessorContext *base.DataProcessorContext
}

// NewMySQLDecryptor returns Decryptor with turned on poison record detection
func NewMySQLDecryptor(clientID []byte, pgDecryptor *postgresql.PgDecryptor, keyStore keystore.KeyStore) *Decryptor {
	logger := log.WithFields(log.Fields{"decryptor": "mysql", "client_id": string(clientID)})
	processorCtx := base.NewDataProcessorContext(clientID, pgDecryptor.IsWithZone(), keyStore).UseContext(logging.SetLoggerToContext(context.Background(), logger))
	decryptor := &Decryptor{
		keyStore:             keyStore,
		binaryDecryptor:      binary.NewBinaryDecryptor(logger),
		Decryptor:            pgDecryptor,
		clientID:             clientID,
		dataProcessorContext: processorCtx,
		log:                  logger}
	// because we will use internal value of pgDecryptor then set it `true` as default on initialization
	pgDecryptor.TurnOnPoisonRecordCheck(true)
	decryptor.SetWholeMatch(pgDecryptor.IsWholeMatch())
	return decryptor
}

// SkipBeginInBlock returns AcraStruct without BeginTag or error if BeginTag not found
func (decryptor *Decryptor) SkipBeginInBlock(block []byte) ([]byte, error) {
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

// MatchZoneBlock returns zone data
func (decryptor *Decryptor) MatchZoneBlock(block []byte) {
	for _, c := range block {
		if !decryptor.MatchZone(c) {
			return
		}
	}
}

// BeginTagIndex returns index where BeginTag is found in AcraStruct
func (decryptor *Decryptor) BeginTagIndex(block []byte) (int, int) {
	if i := bytes.Index(block, base.TagBegin); i != utils.NotFound {
		return i, decryptor.binaryDecryptor.GetTagBeginLength()
	}
	return utils.NotFound, decryptor.GetTagBeginLength()
}

// MatchZoneInBlock finds ZoneId in AcraStruct and marks decryptor matched
func (decryptor *Decryptor) MatchZoneInBlock(block []byte) {
	for {
		// binary format
		i := bytes.Index(block, zone.ZoneIDBegin)
		if i == utils.NotFound {
			break
		} else {
			if decryptor.keyStore.HasZonePrivateKey(block[i : i+zone.ZoneIDBlockLength]) {
				decryptor.GetZoneMatcher().SetMatched(block[i : i+zone.ZoneIDBlockLength])
				return
			}
			block = block[i+1:]
		}
	}
	return
}

// ReadData returns decrypted AcraStruct content
func (decryptor *Decryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
	return decryptor.binaryDecryptor.ReadData(symmetricKey, zoneID, reader)
}

// ReadSymmetricKey returns decrypted SymmetricKey that is used to encrypt AcraStruct content
func (decryptor *Decryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	symmetricKey, rawData, err := decryptor.binaryDecryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		return symmetricKey, rawData, err
	}
	return symmetricKey, rawData, nil
}

func (decryptor *Decryptor) getPoisonPrivateKey() (*keys.PrivateKey, error) {
	keypair, err := decryptor.keyStore.GetPoisonKeyPair()
	if err != nil {
		return nil, err
	}
	return keypair.Private, nil
}

// CheckPoisonRecord check data from reader on poison records
// added to implement base.Decryptor interface
func (decryptor *Decryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	if !decryptor.IsPoisonRecordCheckOn() {
		return false, nil
	}
	block, err := ioutil.ReadAll(reader)
	if err != nil {
		return false, err
	}
	return false, decryptor.checkPoisonRecord(block)
}

// checkPoisonRecord expect that block starts with AcraStruct begin tag
func (decryptor *Decryptor) checkPoisonRecord(block []byte) error {
	if !decryptor.IsPoisonRecordCheckOn() {
		return nil
	}
	if len(block) < base.GetMinAcraStructLength() {
		return nil
	}
	decryptor.Reset()
	data, err := decryptor.SkipBeginInBlock(block)
	if err != nil {
		decryptor.log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSkipBeginInBlock).
			Debugln("Can't skip begin tag in block")
		return nil
	}
	decryptor.log.Debugln("Check block on poison")
	privateKey, err := decryptor.getPoisonPrivateKey()
	if err != nil {
		decryptor.log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).Errorln("Can't load private key for poison records")
		return err
	}
	_, err = decryptor.decryptBlock(bytes.NewReader(data), nil, privateKey)
	if err == nil {
		decryptor.log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Warningln("Recognized poison record")
		if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
			decryptor.log.Debugln("Check poison records")
			if err := decryptor.GetPoisonCallbackStorage().Call(); err != nil {
				decryptor.log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantHandleRecognizedPoisonRecord).
					Errorln("Unexpected error in poison record callbacks")
			}
			decryptor.log.Debugln("Processed all callbacks on poison record")
		}
		return base.ErrPoisonRecord
	}
	return nil
}

// inlinePoisonRecordCheck find acrastructs in block and try to detect poison record
func (decryptor *Decryptor) inlinePoisonRecordCheck(block []byte) error {
	if !decryptor.IsPoisonRecordCheckOn() {
		return nil
	}
	if len(block) < base.GetMinAcraStructLength() {
		return nil
	}
	index := 0
	for {
		beginTagIndex, _ := decryptor.BeginTagIndex(block[index:])
		if beginTagIndex == utils.NotFound {
			break
		} else {
			decryptor.log.Debugln("Found AcraStruct")
			err := decryptor.checkPoisonRecord(block[index+beginTagIndex:])
			if err != nil {
				decryptor.log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check on poison record")
				return err
			}

		}
		index++
	}
	return nil
}

// decryptBlock try to process data after BEGIN_TAG, decrypt and return result
func (decryptor *Decryptor) decryptBlock(reader io.Reader, id []byte, privateKey *keys.PrivateKey) ([]byte, error) {
	logger := decryptor.log.WithField("zone_id", string(decryptor.GetMatchedZoneID()))

	key, _, err := decryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptSymmetricKey).Debugln("Can't unwrap symmetric key")
		return []byte{}, err
	}
	data, err := decryptor.ReadData(key, id, reader)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).Debugln("Can't decrypt data with unwrapped symmetric key")
		return []byte{}, err
	}

	logger.Debugln("Decrypted AcraStruct")
	return data, nil
}

// SetWholeMatch changes decrypt function depending on MatchMode
// if WholeMode: Decryptor tries to find AcraStruct from the beginning of cell
// if InlineMode: Decryptor tries to find AcraStruct in the middle of cell
func (decryptor *Decryptor) SetWholeMatch(value bool) {
	var mode string
	if value {
		decryptor.decryptFunc = decryptor.decryptWholeBlock
		mode = base.DecryptWhole
	} else {
		decryptor.decryptFunc = decryptor.decryptInlineBlock
		mode = base.DecryptInline
	}
	if logging.IsDebugLevel(decryptor.log) {
		decryptor.log = decryptor.log.WithField("decrypt_mode", mode)
	}
}

func (decryptor *Decryptor) decryptWholeBlock(block []byte) ([]byte, error) {
	decryptor.Reset()
	if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
		decryptor.MatchZoneBlock(block)
		// check for poison record
		if err := decryptor.checkPoisonRecord(block); err != nil {
			return nil, err
		}
		return block, nil
	}

	decryptorCtx := decryptor.dataProcessorContext.UseZoneID(decryptor.GetMatchedZoneID())
	newData, err := decryptor.dataProcessor.Process(block, decryptorCtx)
	// true if data has incorrect AcraStruct signature
	dataIsNotAcraStruct := err == base.ErrIncorrectAcraStructTagBegin || err == base.ErrIncorrectAcraStructLength
	if err == nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
		if decryptor.IsWithZone() {
			// reset zone because decryption is successful
			decryptor.ResetZoneMatch()
		}
		return newData, nil
	} else if dataIsNotAcraStruct {
		// it's not AcraStruct, avoid extra check for poison record, don't log any warnings
		// return as is
		return nil, errPlainData
	} else {
		// some error on decryption (has not private key, incorrect zone_id, corrupted AcraStruct, etc);
		decryptor.log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt AcraStruct")
		// check for poison record
		if err := decryptor.checkPoisonRecord(block); err != nil {
			return nil, err
		}
		return block, nil
	}
}

func (decryptor *Decryptor) decryptInlineBlock(block []byte) ([]byte, error) {
	index := 0
	if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
		decryptor.MatchZoneInBlock(block)
		if err := decryptor.inlinePoisonRecordCheck(block); err != nil {
			return nil, err
		}
		return block, nil
	}

	output := bytes.NewBuffer(make([]byte, 0, len(block)))
	for {
		beginTagIndex, tagLength := decryptor.BeginTagIndex(block[index:])
		if beginTagIndex == utils.NotFound {
			output.Write(block[index:])
			break
		}
		output.Write(block[index : index+beginTagIndex])
		index += beginTagIndex
		blockReader := bytes.NewReader(block[index+tagLength:])
		privateKey, err := decryptor.GetPrivateKey()
		if err != nil {
			base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
			decryptor.log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt AcraStruct")
			decryptor.log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).Warningln("Can't load key for AcraStruct")
			if err := decryptor.inlinePoisonRecordCheck(block[index:]); err != nil {
				return nil, err
			}
		} else {
			decrypted, err := decryptor.decryptBlock(blockReader, decryptor.GetMatchedZoneID(), privateKey)
			if err == nil {
				base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
				index += tagLength + (len(block[index+tagLength:]) - blockReader.Len())
				output.Write(decrypted)
				decryptor.ResetZoneMatch()
				continue
			}
			base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
			decryptor.log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt AcraStruct")
			if err := decryptor.inlinePoisonRecordCheck(block[index:]); err != nil {
				return nil, err
			}
		}

		output.Write(block[index : index+1])
		index++
	}
	if len(output.Bytes()) == len(block) {
		return block, errPlainData
	}
	return output.Bytes(), nil
}

// DecryptBlock calls decrypt function on binary block
func (decryptor *Decryptor) DecryptBlock(block []byte) ([]byte, error) {
	return decryptor.decryptFunc(block)
}

// SetDataProcessor replace current with new processor
func (decryptor *Decryptor) SetDataProcessor(processor base.DataProcessor) {
	decryptor.dataProcessor = processor
}
