/*
Copyright 2018, Cossack Labs Limited
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
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/hmac"
	hashDecryptor "github.com/cossacklabs/acra/hmac/decryptor"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/masking"
	"github.com/cossacklabs/acra/pseudonymization"
	"github.com/cossacklabs/acra/pseudonymization/common"
)

type proxyFactory struct {
	setting   base.ProxySetting
	keystore  keystore.DecryptionKeyStore
	tokenizer common.Pseudoanonymizer
}

// NewProxyFactory return new proxyFactory
func NewProxyFactory(proxySetting base.ProxySetting, store keystore.DecryptionKeyStore, tokenizer common.Pseudoanonymizer) (base.ProxyFactory, error) {
	return &proxyFactory{
		setting:   proxySetting,
		keystore:  store,
		tokenizer: tokenizer,
	}, nil
}

// New return postgresql proxy implementation
func (factory *proxyFactory) New(clientID []byte, clientSession base.ClientSession) (base.Proxy, error) {
	sqlParser := factory.setting.SQLParser()
	proxy, err := NewPgProxy(clientSession, sqlParser, factory.setting)
	if err != nil {
		return nil, err
	}

	registryHandler := crypto.NewRegistryHandler(factory.keystore)
	envelopeDetector := crypto.NewEnvelopeDetector()

	var containerDetector base.DecryptionSubscriber = envelopeDetector

	if base.OldContainerDetectionOn {
		containerDetector = crypto.NewOldContainerDetectorWrapper(envelopeDetector)
	}

	// default behaviour that always decrypts AcraStructs
	var decryptorDataProcessor base.DataProcessor = registryHandler

	schemaStore := factory.setting.TableSchemaStore()
	storeMask := schemaStore.GetGlobalSettingsMask()
	// register only if masking/tokenization/searching will be used
	if !base.OnlyDefaultEncryptorSettings(schemaStore) {
		// register Query processor first before other processors because it match SELECT queries for ColumnEncryptorConfig structs
		// and store it in AccessContext for next decryptions/encryptions and all other processors rely on that
		// use nil dataEncryptor to avoid extra computations
		queryEncryptor, err := encryptor.NewPostgresqlQueryEncryptor(factory.setting.TableSchemaStore(), sqlParser, nil)
		if err != nil {
			return nil, err
		}
		proxy.AddQueryObserver(queryEncryptor)
		proxy.SubscribeOnAllColumnsDecryption(queryEncryptor)
	}

	decoderProcessor, err := NewPgSQLDataDecoderProcessor()
	if err != nil {
		return nil, err
	}
	encoderProcessor, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		return nil, err
	}
	// register first to decode all data into text/binary formats expected by handlers according to client/database
	//requested formats and ColumnEncryptionSetting
	proxy.SubscribeOnAllColumnsDecryption(decoderProcessor)

	// poison record processor should be first
	if factory.setting.PoisonRecordCallbackStorage() != nil && factory.setting.PoisonRecordCallbackStorage().HasCallbacks() {
		// setting PoisonRecords callback for CryptoHandlers inside registry
		poisonDetector := crypto.NewPoisonRecordsRecognizer(factory.setting.KeyStore(), registryHandler)
		poisonDetector.SetPoisonRecordCallbacks(factory.setting.PoisonRecordCallbackStorage())

		envelopeDetector.AddCallback(poisonDetector)
	}

	chainEncryptors := make([]encryptor.DataEncryptor, 0, 10)
	if storeMask&config.SettingTokenizationFlag == config.SettingTokenizationFlag {
		tokenizer, err := pseudonymization.NewDataTokenizer(factory.tokenizer)
		if err != nil {
			return nil, err
		}

		tokenProcessor, err := pseudonymization.NewTokenProcessor(tokenizer)
		if err != nil {
			return nil, err
		}
		proxy.SubscribeOnAllColumnsDecryption(tokenProcessor)
		tokenEncryptor, err := pseudonymization.NewTokenEncryptor(tokenizer)
		if err != nil {
			return nil, err
		}
		chainEncryptors = append(chainEncryptors, tokenEncryptor)
	}

	chainEncryptors = append(chainEncryptors, crypto.NewEncryptHandler(registryHandler))

	var hmacProcessor *hmac.Processor
	if storeMask&config.SettingSearchFlag == config.SettingSearchFlag {
		hmacProcessor = hmac.NewHMACProcessor(factory.keystore)
		proxy.SubscribeOnAllColumnsDecryption(hmacProcessor)
		searchableAcrawriterEncryptor, err := hmac.NewSearchableEncryptor(factory.keystore, registryHandler, registryHandler)
		if err != nil {
			return nil, err
		}
		chainEncryptors = append(chainEncryptors, searchableAcrawriterEncryptor)
		acraBlockStructHashEncryptor := hashDecryptor.NewPostgresqlHashQuery(factory.keystore, schemaStore, registryHandler)
		proxy.AddQueryObserver(acraBlockStructHashEncryptor)
	}

	if storeMask&config.SettingMaskingFlag == config.SettingMaskingFlag {
		decryptorDataProcessor, err = masking.NewProcessor(registryHandler)
		if err != nil {
			return nil, err
		}

		maskingDataEncryptor := encryptor.NewChainDataEncryptor([]encryptor.DataEncryptor{registryHandler}...)
		maskingEncryptor, err := masking.NewMaskingDataEncryptor(factory.keystore, maskingDataEncryptor)
		if err != nil {
			return nil, err
		}
		chainEncryptors = append(chainEncryptors, maskingEncryptor)

	}
	decrypt := crypto.NewDecryptHandler(factory.keystore, decryptorDataProcessor)
	envelopeDetector.AddCallback(decrypt)
	// used for decryption standalone AcraBlocks and searchable
	proxy.SubscribeOnAllColumnsDecryption(containerDetector)

	if hmacProcessor != nil {
		// added same hmacProcessor to check hmac validation after decryption
		proxy.SubscribeOnAllColumnsDecryption(hmacProcessor)
	}

	chainEncryptors = append(chainEncryptors, crypto.NewReEncryptHandler(factory.keystore))

	// register query processors/encryptors only if have some
	queryDataEncryptor := encryptor.NewChainDataEncryptor(chainEncryptors...)
	queryEncryptor, err := encryptor.NewPostgresqlQueryEncryptor(factory.setting.TableSchemaStore(), sqlParser, queryDataEncryptor)
	if err != nil {
		return nil, err
	}
	proxy.AddQueryObserver(queryEncryptor)
	// register last to encode all data into correct format according to client/database requested formats
	// and ColumnEncryptionSetting
	proxy.SubscribeOnAllColumnsDecryption(encoderProcessor)

	return proxy, nil
}
