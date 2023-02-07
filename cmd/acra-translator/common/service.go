package common

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/logging"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
)

// ITranslatorService interface introduce all supported methods by Acra-Translator
type ITranslatorService interface {
	Decrypt(ctx context.Context, acraStruct, clientID, additionalContext []byte) ([]byte, error)
	Encrypt(ctx context.Context, data, clientID, additionalContext []byte) ([]byte, error)
	EncryptSearchable(ctx context.Context, data, clientID, additionalContext []byte) (SearchableResponse, error)
	DecryptSearchable(ctx context.Context, data, hash, clientID, additionalContext []byte) ([]byte, error)
	GenerateQueryHash(context context.Context, data, clientID, additionalContext []byte) ([]byte, error)
	Tokenize(ctx context.Context, data interface{}, dataType tokenCommon.TokenType, clientID, additionalContext []byte) (interface{}, error)
	Detokenize(ctx context.Context, data interface{}, dataType tokenCommon.TokenType, clientID, additionalContext []byte) (interface{}, error)
	EncryptSymSearchable(ctx context.Context, data, clientID, additionalContext []byte) (SearchableResponse, error)
	DecryptSymSearchable(ctx context.Context, data, hash, clientID, additionalContext []byte) ([]byte, error)
	EncryptSym(ctx context.Context, data, clientID, additionalContext []byte) ([]byte, error)
	DecryptSym(ctx context.Context, acraBlock, clientID, additionalContext []byte) ([]byte, error)
}

// TranslatorService service that implements all Acra-Translator functions
type TranslatorService struct {
	data           *TranslatorData
	handler        crypto.RegistryHandler
	poisonDetector *crypto.EnvelopeDetector
}

// NewTranslatorService return new initialized TranslatorService
func NewTranslatorService(translatorData *TranslatorData) (*TranslatorService, error) {
	registryHandler := crypto.NewRegistryHandler(translatorData.Keystorage)
	poisonEnvelopeDetector := crypto.NewEnvelopeDetector()
	if translatorData.PoisonRecordCallbacks != nil && translatorData.PoisonRecordCallbacks.HasCallbacks() {
		// setting PoisonRecords callback for CryptoHandlers inside registry
		poisonDetector := crypto.NewPoisonRecordsRecognizer(translatorData.Keystorage, registryHandler)
		poisonDetector.SetPoisonRecordCallbacks(translatorData.PoisonRecordCallbacks)
		poisonEnvelopeDetector.AddCallback(poisonDetector)
	}
	return &TranslatorService{data: translatorData, handler: registryHandler, poisonDetector: poisonEnvelopeDetector}, nil
}

// Errors possible during decrypting AcraStructs.
var (
	ErrCantDecrypt                      = errors.New("can't decrypt data")
	ErrClientIDRequired                 = errors.New("clientID is empty")
	ErrCantEncrypt                      = errors.New("can't encrypt data")
	ErrZoneIDAdditionalDataNotSupported = errors.New("AdditionalContext and additional data are not supported")
)

// Decrypt AcraStruct using ClientID
func (service *TranslatorService) Decrypt(ctx context.Context, acraStruct, clientID, additionalContext []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "Decrypt"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")

	if len(clientID) == 0 {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorClientIDMissing).Errorln("Request without ClientID not allowed")
		return nil, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}

	accessContext := base.NewAccessContext(base.WithClientID(clientID))

	dataCtx := base.SetAccessContextToContext(ctx, accessContext)
	dataContext := &base.DataProcessorContext{Keystore: service.data.Keystorage, Context: dataCtx}
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraStructEnvelopeID)
	if err != nil {
		return nil, ErrCantDecrypt
	}

	data, decryptErr := service.handler.DecryptWithHandler(handler, acraStruct, dataContext)
	if decryptErr != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.LabelStatusFail).Inc()
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).WithError(decryptErr).Errorln("Can't decrypt AcraStruct")
		_, _, err = service.poisonDetector.OnColumn(dataCtx, acraStruct)
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check for poison record, possible missing Poison record decryption key")
			return nil, ErrCantDecrypt
		}
		// don't show users that we found poison record
		return nil, ErrCantDecrypt
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.LabelStatusSuccess).Inc()
	return data, nil
}

// Encrypt AcraStruct using ClientID
func (service *TranslatorService) Encrypt(ctx context.Context, data, clientID, additionalContext []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "Encrypt"})
	logger.Debugln("Process request to encrypt data")
	defer logger.Debugln("End processing request")

	if len(clientID) == 0 {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorClientIDMissing).Errorln("GRPC request without ClientID not allowed")
		return nil, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}
	id := clientID
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraStructEnvelopeID)
	if err != nil {
		logger.
			WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).
			WithError(err).
			WithField("handler_id", crypto.AcraStructEnvelopeID).
			Errorln("Can't get crypt handler by ID")
		// don't show users that we found poison record
		return nil, ErrCantDecrypt
	}

	data, encryptErr := service.handler.EncryptWithHandler(handler, id, data)
	if encryptErr != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).WithError(encryptErr).Errorln("Can't encrypt data")
		// don't show users that we found poison record
		return nil, ErrCantEncrypt
	}
	return data, nil
}

// SearchableResponse store EncryptedData that may be AcraStruct or AcraBLock and searchable Hash
type SearchableResponse struct {
	EncryptedData []byte
	Hash          []byte
}

// EncryptSearchable generate AcraStruct using ClientID and searchable hash
func (service *TranslatorService) EncryptSearchable(ctx context.Context, data, clientID, additionalContext []byte) (SearchableResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "Encrypt (searchable)"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")
	if clientID == nil {
		logger.Errorln("Empty ClientID")
		return SearchableResponse{}, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return SearchableResponse{}, ErrZoneIDAdditionalDataNotSupported
	}

	logger.Debugln("Load secret key for HMAC from KeyStore")
	hmacKey, err := service.data.Keystorage.GetHMACSecretKey(clientID)
	if err != nil {
		logger.WithError(err).Errorln("Can't load HMAC key")
		return SearchableResponse{}, ErrKeysNotFound
	}
	logger.Debugln("Generate HMAC")
	dataHash := hmac.GenerateHMAC(hmacKey, data)
	logger.Debugln("Create AcraStruct")
	id := clientID
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraStructEnvelopeID)
	if err != nil {
		return SearchableResponse{}, ErrEncryptionFailed
	}

	acraStruct, err := service.handler.EncryptWithHandler(handler, id, data)
	if err != nil {
		logger.WithError(err).Errorln("Can't create AcraStruct")
		return SearchableResponse{}, ErrEncryptionFailed
	}
	return SearchableResponse{EncryptedData: acraStruct, Hash: dataHash}, nil

}

// DecryptSearchable decrypt AcraStruct using ClientID and then verify hash
func (service *TranslatorService) DecryptSearchable(ctx context.Context, data, hash, clientID, additionalContext []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "Decrypt (searchable)"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")
	if clientID == nil {
		logger.Errorln("Empty ClientID")
		return nil, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}
	logger.Debugln("Load secret key for HMAC from KeyStore")
	// if wasn't provided Hash as extra field than we expect that AcraStruct concatenated with hash
	dataToDecrypt := data
	if hash != nil {
		dataToDecrypt = append(hash, data...)
	}
	logger.Debugln("Decrypt AcraStruct")
	hashPart, containerData := hmac.ExtractHashAndData(dataToDecrypt)
	if hashPart == nil {
		return nil, ErrCantDecrypt
	}
	accessContext := base.NewAccessContext(base.WithClientID(clientID))
	dataCtx := base.SetAccessContextToContext(ctx, accessContext)
	dataContext := &base.DataProcessorContext{Keystore: service.data.Keystorage, Context: dataCtx}
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraStructEnvelopeID)
	if err != nil {
		return nil, ErrCantDecrypt
	}

	decrypted, err := service.handler.DecryptWithHandler(handler, containerData, dataContext)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).WithError(err).Errorln("Can't decrypt AcraStruct")
		_, _, poisonErr := service.poisonDetector.OnColumn(dataCtx, containerData)
		if poisonErr != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check for poison record with AcraStruct, possible missing Poison record decryption key")
			return nil, ErrDecryptionFailed
		}
		return data, ErrDecryptionFailed
	}
	// validate hash
	if !hashPart.IsEqual(decrypted, clientID, service.data.Keystorage) {
		return nil, ErrDecryptionFailed
	}

	return decrypted, nil
}

// GenerateQueryHash generates searchable hash for data
func (service *TranslatorService) GenerateQueryHash(context context.Context, data, clientID, additionalContext []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(context)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "GenerateQueryHash"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")
	if clientID == nil {
		logger.Errorln("Empty clientID")
		return nil, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}
	logger.Debugln("Load secret key for HMAC from KeyStore")
	key, err := service.data.Keystorage.GetHMACSecretKey(clientID)
	if err != nil {
		logger.WithError(err).Errorln("Can't load HMAC key")
		return nil, ErrKeysNotFound
	}
	logger.Debugln("Generate HMAC")
	hash := hmac.GenerateHMAC(key, data)
	return hash, nil
}

// Tokenize data from request according to TokenType using ClientID
func (service *TranslatorService) Tokenize(ctx context.Context, data interface{}, dataType tokenCommon.TokenType, clientID, additionalContext []byte) (interface{}, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "Tokenize"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "Tokenize"}).Debugln("End processing request")
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}
	tokenContext := tokenCommon.TokenContext{ClientID: clientID}
	response, err := service.data.Tokenizer.AnonymizeConsistently(data, tokenContext, dataType)
	if err != nil {
		logger.WithError(err).Errorln("Can't tokenize")
		return nil, ErrTokenize
	}
	return response, nil
}

// Detokenize data from request according to TokenType using ClientID
func (service *TranslatorService) Detokenize(ctx context.Context, data interface{}, dataType tokenCommon.TokenType, clientID, additionalContext []byte) (interface{}, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "Detokenize"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request to detokenize token")
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}
	tokenContext := tokenCommon.TokenContext{ClientID: clientID}
	switch dataType {
	case tokenCommon.TokenType_Bytes, tokenCommon.TokenType_Email, tokenCommon.TokenType_Int32, tokenCommon.TokenType_Int64, tokenCommon.TokenType_String:
		sourceData, err := service.data.Tokenizer.Deanonymize(data, tokenContext, dataType)
		if err != nil {
			logger.WithField("type", dataType).WithError(err).Errorln("Can't tokenize data")
			return nil, ErrDetokenize
		}
		return sourceData, nil
	default:
		logger.WithField("type", dataType).Errorln("Unsupported token type")
		return nil, tokenCommon.ErrUnknownTokenType
	}
}

// Errors related with gRPC requests
var (
	ErrKeysNotFound     = errors.New("keys not found")
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrDetokenize       = errors.New("can't detokenize")
	ErrTokenize         = errors.New("can't tokenize")
)

// EncryptSymSearchable encrypts data with AcraBlock using ClientID and searchable hash
func (service *TranslatorService) EncryptSymSearchable(ctx context.Context, data, clientID, additionalContext []byte) (SearchableResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "EncryptSym (searchable)"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")
	if clientID == nil {
		logger.Errorln("Empty ClientID")
		return SearchableResponse{}, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return SearchableResponse{}, ErrZoneIDAdditionalDataNotSupported
	}
	logger.Debugln("Load secret key for HMAC from KeyStore")
	hmacKey, err := service.data.Keystorage.GetHMACSecretKey(clientID)
	if err != nil {
		logger.WithError(err).Errorln("Can't load HMAC key")
		return SearchableResponse{}, ErrKeysNotFound
	}
	logger.Debugln("Generate HMAC")
	dataHash := hmac.GenerateHMAC(hmacKey, data)
	logger.Debugln("Create AcraBlock")
	id := clientID
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraBlockEnvelopeID)
	if err != nil {
		return SearchableResponse{}, ErrEncryptionFailed
	}

	acraBlock, err := service.handler.EncryptWithHandler(handler, id, data)
	if err != nil {
		logger.WithError(err).Errorln("Can't create AcraBlock")
		return SearchableResponse{}, ErrEncryptionFailed
	}
	return SearchableResponse{Hash: dataHash, EncryptedData: acraBlock}, nil
}

// DecryptSymSearchable decrypt AcraBlock using ClientID and verify hash
func (service *TranslatorService) DecryptSymSearchable(ctx context.Context, data, hash, clientID, additionalContext []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "DecryptSym (searchable)"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")
	if clientID == nil {
		logger.Errorln("Empty ClientID")
		return nil, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}

	logger.Debugln("Load secret key for HMAC from KeyStore")
	// if wasn't provided Hash as extra field than we expect that AcraStruct concatenated with hash
	dataToDecrypt := data
	if hash != nil {
		dataToDecrypt = append(hash, data...)
	}
	logger.Debugln("Decrypt AcraBlock")
	accessContext := base.NewAccessContext(base.WithClientID(clientID))
	dataCtx := base.SetAccessContextToContext(ctx, accessContext)
	dataContext := &base.DataProcessorContext{Keystore: service.data.Keystorage, Context: dataCtx}
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraBlockEnvelopeID)
	if err != nil {
		return nil, ErrCantDecrypt
	}

	hashPart, containerData := hmac.ExtractHashAndData(dataToDecrypt)
	if hashPart == nil {
		// check poison records
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraBlock).
			WithError(err).
			Errorln("Can't split ciphertext to hash and encrypted data")
		_, _, err := service.poisonDetector.OnColumn(dataCtx, dataToDecrypt)
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check for poison record with AcraBlock, possible missing Poison record decryption key")
			return nil, ErrCantDecrypt
		}
		return nil, ErrCantDecrypt
	}
	decrypted, err := service.handler.DecryptWithHandler(handler, containerData, dataContext)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraBlock).WithError(err).Errorln("Can't decrypt AcraBlock")
		_, _, err = service.poisonDetector.OnColumn(dataCtx, containerData)
		if err != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check for poison record with AcraBlock, possible missing Poison record decryption key")
			return nil, ErrCantDecrypt
		}
		return data, ErrCantDecrypt
	}
	// validate hash
	if !hashPart.IsEqual(decrypted, clientID, service.data.Keystorage) {
		return nil, ErrCantDecrypt
	}

	return decrypted, nil
}

// EncryptSym encrypts data with AcraBlock using ClientID
func (service *TranslatorService) EncryptSym(ctx context.Context, data, clientID, additionalContext []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "EncryptSym"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")
	if clientID == nil {
		logger.Errorln("Empty ClientID")
		return nil, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}

	logger.Debugln("Create AcraBlock")
	id := clientID
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraBlockEnvelopeID)
	if err != nil {
		return nil, ErrEncryptionFailed
	}

	acraBlock, err := service.handler.EncryptWithHandler(handler, id, data)
	if err != nil {
		logger.WithError(err).Errorln("Can't create AcraBlock")
		return nil, ErrEncryptionFailed
	}
	return acraBlock, nil
}

// DecryptSym decrypts AcraBlock using ClientID
func (service *TranslatorService) DecryptSym(ctx context.Context, acraBlock, clientID, additionalContext []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger = logger.WithFields(logrus.Fields{"client_id": string(clientID), "context": string(additionalContext), "operation": "DecryptSym"})
	logger.Debugln("New request")
	defer logger.Debugln("End processing request")
	if clientID == nil {
		logger.Errorln("Empty ClientID")
		return nil, ErrClientIDRequired
	}
	if additionalContext != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorZoneIDAndAdditionalDataNotSupported).Errorln("AdditionalContext and additional data are not supported")
		return nil, ErrZoneIDAdditionalDataNotSupported
	}

	logger.Debugln("Decrypt AcraBlock")
	accessContext := base.NewAccessContext(base.WithClientID(clientID))
	dataCtx := base.SetAccessContextToContext(ctx, accessContext)
	dataContext := &base.DataProcessorContext{Keystore: service.data.Keystorage, Context: dataCtx}
	handler, err := crypto.GetHandlerByEnvelopeID(crypto.AcraBlockEnvelopeID)
	if err != nil {
		return nil, ErrCantDecrypt
	}

	decrypted, err := service.handler.DecryptWithHandler(handler, acraBlock, dataContext)
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.LabelStatusFail).Inc()
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraBlock).WithError(err).Errorln("Can't decrypt AcraBlock")
		_, _, poisonErr := service.poisonDetector.OnColumn(dataCtx, acraBlock)
		if poisonErr != nil {
			logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check for poison record with AcraBlock, possible missing Poison record decryption key")
			return nil, ErrCantDecrypt
		}
		return acraBlock, ErrCantDecrypt
	}

	base.AcrastructDecryptionCounter.WithLabelValues(base.LabelStatusSuccess).Inc()
	return decrypted, nil
}
