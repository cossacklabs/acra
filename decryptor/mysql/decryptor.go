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

// Package mysql contains MySQLDecryptor that reads data from MySQL database, finds AcraStructs and decrypt them.
package mysql

import (
	"bytes"
	"context"
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

// MySQLDecryptor used to decrypt AcraStruct from MySQL fields
type MySQLDecryptor struct {
	base.Decryptor
	binaryDecryptor      *binary.BinaryDecryptor
	keyStore             keystore.KeyStore
	decryptFunc          decryptFunc
	log                  *log.Entry
	clientID             []byte
	dataProcessor        base.DataProcessor
	dataProcessorContext *base.DataProcessorContext
}

// Possible decryption modes: AcraStruct can start from beginning of cell, or be part of the cell
const (
	DecryptWhole  = "whole_block"
	DecryptInline = "inline_block"
)

// NewMySQLDecryptor returns MySQLDecryptor with turned on poison record detection
func NewMySQLDecryptor(clientID []byte, pgDecryptor *postgresql.PgDecryptor, keyStore keystore.KeyStore) *MySQLDecryptor {
	logger := log.WithFields(log.Fields{"decryptor": "mysql", "client_id": string(clientID)})
	processorCtx := base.NewDataProcessorContext(clientID, pgDecryptor.IsWithZone(), keyStore).UseContext(logging.SetLoggerToContext(context.Background(), logger))
	decryptor := &MySQLDecryptor{
		keyStore:             keyStore,
		binaryDecryptor:      binary.NewBinaryDecryptor(),
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
func (decryptor *MySQLDecryptor) SkipBeginInBlock(block []byte) ([]byte, error) {
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
func (decryptor *MySQLDecryptor) MatchZoneBlock(block []byte) {
	for _, c := range block {
		if !decryptor.MatchZone(c) {
			return
		}
	}
}

// BeginTagIndex returns index where BeginTag is found in AcraStruct
func (decryptor *MySQLDecryptor) BeginTagIndex(block []byte) (int, int) {
	if i := bytes.Index(block, base.TagBegin); i != utils.NotFound {
		return i, decryptor.binaryDecryptor.GetTagBeginLength()
	}
	return utils.NotFound, decryptor.GetTagBeginLength()
}

// MatchZoneInBlock finds ZoneId in AcraStruct and marks decryptor matched
func (decryptor *MySQLDecryptor) MatchZoneInBlock(block []byte) {
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
func (decryptor *MySQLDecryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
	return decryptor.binaryDecryptor.ReadData(symmetricKey, zoneID, reader)
}

// ReadSymmetricKey returns decrypted SymmetricKey that is used to encrypt AcraStruct content
func (decryptor *MySQLDecryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	symmetricKey, rawData, err := decryptor.binaryDecryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		return symmetricKey, rawData, err
	}
	return symmetricKey, rawData, nil
}

func (decryptor *MySQLDecryptor) getPoisonPrivateKey() (*keys.PrivateKey, error) {
	keypair, err := decryptor.keyStore.GetPoisonKeyPair()
	if err != nil {
		return nil, err
	}
	return keypair.Private, nil
}

// CheckPoisonRecord check data from reader on poison records
// added to implement base.Decryptor interface
func (decryptor *MySQLDecryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	if !decryptor.IsPoisonRecordCheckOn() {
		return false, nil
	}
	block, err := ioutil.ReadAll(reader)
	if err != nil {
		return false, err
	}
	return false, decryptor.checkPoisonRecord(block)
}

func (decryptor *MySQLDecryptor) checkPoisonRecord(block []byte) error {
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
	_, err = decryptor.decryptBlock(bytes.NewReader(data), nil, decryptor.getPoisonPrivateKey)
	if err == nil {
		decryptor.log.Warningln("Recognized poison record")
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
func (decryptor *MySQLDecryptor) inlinePoisonRecordCheck(block []byte) error {
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
			log.Debugln("Found AcraStruct")
			err := decryptor.checkPoisonRecord(block[index+beginTagIndex:])
			if err != nil {
				decryptor.log.WithError(err).Errorln("Can't check on poison record")
				return err
			}

		}
		index++
	}
	return nil
}

type getKeyFunc func() (*keys.PrivateKey, error)

// decryptBlock try to process data after BEGIN_TAG, decrypt and return result
func (decryptor *MySQLDecryptor) decryptBlock(reader io.Reader, id []byte, keyFunc getKeyFunc) ([]byte, error) {
	logger := decryptor.log.WithField("zone_id", string(id))
	privateKey, err := keyFunc()
	if err != nil {
		logger.WithError(err).Warningln("Can't read private key")
		return []byte{}, err
	}
	key, _, err := decryptor.ReadSymmetricKey(privateKey, reader)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptSymmetricKey).Warningln("Can't unwrap symmetric key")
		return []byte{}, err
	}
	data, err := decryptor.ReadData(key, id, reader)
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).Warningln("Can't decrypt data with unwrapped symmetric key")
		return []byte{}, err
	}
	logger.Infoln("Decrypted AcraStruct")
	return data, nil
}

// SetWholeMatch changes decrypt function depending on MatchMode
// if WholeMode: Decryptor tries to find AcraStruct from the beginning of cell
// if InlineMode: Decryptor tries to find AcraStruct in the middle of cell
func (decryptor *MySQLDecryptor) SetWholeMatch(value bool) {
	if value {
		decryptor.decryptFunc = decryptor.decryptWholeBlock
		decryptor.log = decryptor.log.WithField("decrypt_mode", DecryptWhole)
	} else {
		decryptor.decryptFunc = decryptor.decryptInlineBlock
		decryptor.log = decryptor.log.WithField("decrypt_mode", DecryptInline)
	}
}

func (decryptor *MySQLDecryptor) decryptWholeBlock(block []byte) ([]byte, error) {
	decryptor.Reset()
	if !decryptor.IsWithZone() || decryptor.IsMatchedZone() {
		ctx := decryptor.dataProcessorContext.UseZoneID(decryptor.GetMatchedZoneID())
		newData, err := decryptor.dataProcessor.Process(block, ctx)
		if err != nil {
			base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
			if err := decryptor.checkPoisonRecord(block); err != nil {
				return nil, err
			}
			decryptor.log.Debugln("Can't decrypt block")
			return nil, err
		}
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
		if decryptor.IsWithZone() && err == nil && len(newData) != len(block) {
			// reset zone because decryption is successful
			decryptor.ResetZoneMatch()
		}
		return newData, err
	}
	decryptor.MatchZoneBlock(block)
	if err := decryptor.checkPoisonRecord(block); err != nil {
		return nil, err
	}
	return block, nil
}

func (decryptor *MySQLDecryptor) decryptInlineBlock(block []byte) ([]byte, error) {
	var output bytes.Buffer
	index := 0
	decryptor.log.Debugf("block len %v", len(block))
	if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
		decryptor.MatchZoneInBlock(block)
		if err := decryptor.inlinePoisonRecordCheck(block); err != nil {
			return nil, err
		}
		return block, nil
	}
	for index < len(block) {
		beginTagIndex, tagLength := decryptor.BeginTagIndex(block[index:])
		if beginTagIndex == utils.NotFound {
			output.Write(block[index:])
			return output.Bytes(), nil
		}
		output.Write(block[index : index+beginTagIndex])
		index += beginTagIndex
		blockReader := bytes.NewReader(block[index+tagLength:])
		decrypted, err := decryptor.decryptBlock(blockReader, decryptor.GetMatchedZoneID(), decryptor.GetPrivateKey)
		if err != nil {
			base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
			if err := decryptor.inlinePoisonRecordCheck(block[index:]); err != nil {
				return nil, err
			}
			output.Write(block[index : index+1])
			index++
			decryptor.log.Debugln("Can't decrypt block")
			continue
		}
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
		index += tagLength + (len(block[beginTagIndex+tagLength:]) - blockReader.Len())
		output.Write(decrypted)
		decryptor.ResetZoneMatch()
	}
	return output.Bytes(), nil
}

// DecryptBlock calls decrypt function on binary block
func (decryptor *MySQLDecryptor) DecryptBlock(block []byte) ([]byte, error) {
	return decryptor.decryptFunc(block)
}

// SetDataProcessor replace current with new processor
func (decryptor *MySQLDecryptor) SetDataProcessor(processor base.DataProcessor) {
	decryptor.dataProcessor = processor
}
