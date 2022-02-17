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

// Package poison generates poison record with desired length using provided key. Poison records are the records
// specifically designed and crafted in such a way that they wouldn't be queried by a user
// under normal circumstances. Read more in AcraPoisonRecordsMaker package.
//
// https://github.com/cossacklabs/acra/wiki/Intrusion-detection
package poison

import (
	"context"
	"crypto/rand"
	math_rand "math/rand"
	"time"

	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// Poison records length constants
const (
	UseDefaultDataLength = -1
	DefaultDataLength    = 100
)

func createPoisonRecordData(dataLength int) ([]byte, error) {
	// data length can't be zero
	if dataLength == UseDefaultDataLength {
		math_rand.Seed(time.Now().UnixNano())
		// from 1 to DefaultDataLength
		dataLength = 1 + int(math_rand.Int31n(DefaultDataLength-1))
	}
	// +1 for excluding 0
	data := make([]byte, dataLength)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// CreatePoisonRecord generates AcraStruct encrypted with Poison Record public key
func CreatePoisonRecord(keystore keystore.PoisonKeyStore, dataLength int) ([]byte, error) {
	data, err := createPoisonRecordData(dataLength)
	if err != nil {
		return nil, err
	}
	poisonKeypair, err := keystore.GetPoisonKeyPair()
	if err != nil {
		return nil, err
	}

	acraStruct, err := acrastruct.CreateAcrastruct(data, poisonKeypair.Public, nil)
	if err != nil {
		return nil, err
	}

	return crypto.SerializeEncryptedData(acraStruct, crypto.AcraStructEnvelopeID)
}

// CreateSymmetricPoisonRecord generates AcraBlock encrypted with Poison Record symmetric key
func CreateSymmetricPoisonRecord(keyStore keystore.PoisonKeyStore, dataLength int) ([]byte, error) {
	data, err := createPoisonRecordData(dataLength)
	if err != nil {
		return nil, err
	}
	symmetricKeys, err := keyStore.GetPoisonSymmetricKeys()
	if err != nil {
		return nil, err
	}
	if len(symmetricKeys) <= 0 {
		return nil, keystore.ErrKeysNotFound
	}

	acraBlock, err := acrablock.CreateAcraBlock(data, symmetricKeys[0], nil)
	if err != nil {
		return nil, err
	}

	return crypto.SerializeEncryptedData(acraBlock, crypto.AcraBlockEnvelopeID)
}

// RecordProcessorKeyStore interface with required methods for RecordProcessor
type RecordProcessorKeyStore interface {
	GetPoisonPrivateKeys() ([]*keys.PrivateKey, error)
	GetPoisonSymmetricKeys() ([][]byte, error)
}

// RecordProcessor implements DecryptionSubscriber interface to subscribe on AcraStructs and detect poison records
type RecordProcessor struct {
	keystore       RecordProcessorKeyStore
	callbacks      base.PoisonRecordCallbackStorage
	poisonDetector *crypto.EnvelopeDetector
}

//// NewRecordProcessor return new RecordProcessor
//func NewRecordProcessor(keystore RecordProcessorKeyStore, callbacks base.PoisonRecordCallbackStorage) (*RecordProcessor, error) {
//	registryHandler := crypto.NewRegistryHandler(crypto.NewPoisonRecordKeyStoreWrapper(keystore))
//	envelopeDetector := crypto.NewEnvelopeDetector()
//	if callbacks != nil && callbacks.HasCallbacks() {
//		// setting PoisonRecords callback for CryptoHandlers inside registry
//		poisonDetector := crypto.NewPoisonRecordsRecognizer(keystore, registryHandler)
//		poisonDetector.SetPoisonRecordCallbacks(callbacks)
//		envelopeDetector.AddCallback(poisonDetector)
//	}
//	return &RecordProcessor{keystore, callbacks, envelopeDetector}, nil
//}

// ID return string id of processor
func (processor *RecordProcessor) ID() string {
	return "RecordProcessor"
}

// OnColumn try to detect any poison record (inlined too) in data and call callbacks from PoisonRecordCallbackStorage
func (processor *RecordProcessor) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Debugln("Called OnColumn in poison processor")
	// safe to pass same buffer because processor will return same data
	if _, err := acrastruct.ProcessAcraStructs(ctx, data, data, processor); err != nil {
		return ctx, data, err
	}
	_, err := acrablock.ProcessAcraBlocks(ctx, data, data, processor)
	return ctx, data, err
}

// OnAcraStruct callback for every recognized AcraStruct which try to decrypt with poison record private keys
func (processor *RecordProcessor) OnAcraStruct(ctx context.Context, acrastructBlock []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	if !processor.callbacks.HasCallbacks() {
		logger.Debugln("Skip poison record check due to empty callbacks")
		return acrastructBlock, nil
	}
	logger.Debugln("Called on AcraStruct in poison processor")
	poisonKeys, err := processor.keystore.GetPoisonPrivateKeys()
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).WithError(err).Errorln("Can't load poison keypair")
		return acrastructBlock, err
	}
	defer utils.ZeroizePrivateKeys(poisonKeys)

	_, err = acrastruct.DecryptRotatedAcrastruct(acrastructBlock, poisonKeys, nil)
	if err == nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Warningln("Recognized poison record")
		if processor.callbacks.HasCallbacks() {
			err = processor.callbacks.Call()
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Unexpected error in poison record callbacks")
			}
			logger.Debugln("Processed all callbacks on poison record")
			return acrastructBlock, err
		}
		return acrastructBlock, nil
	}
	return acrastructBlock, nil
}

// OnAcraBlock callback for every recognized AcraBlock which try to decrypt with poison record symmetric keys
func (processor *RecordProcessor) OnAcraBlock(ctx context.Context, acraBlock acrablock.AcraBlock) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	if !processor.callbacks.HasCallbacks() {
		logger.Debugln("Skip poison record check due to empty callbacks")
		return acraBlock, nil
	}
	logger.Debugln("Called on AcraBlock in poison processor")
	poisonKeys, err := processor.keystore.GetPoisonSymmetricKeys()
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).WithError(err).Errorln("Can't load poison symmetric keys")
		return acraBlock, err
	}
	defer utils.ZeroizeSymmetricKeys(poisonKeys)

	_, err = acraBlock.Decrypt(poisonKeys, nil)
	if err == nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Warningln("Recognized poison record")
		if processor.callbacks.HasCallbacks() {
			err = processor.callbacks.Call()
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Unexpected error in poison record callbacks")
			}
			logger.Debugln("Processed all callbacks on poison record")
			return acraBlock, err
		}
		return acraBlock, nil
	}
	return acraBlock, nil
}
