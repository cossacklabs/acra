/*
Copyright 2020, Cossack Labs Limited

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

package grpc_api

import (
	"errors"
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/logging"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// ErrEmptyClientID error used if ClientID required in request but not provided
var ErrEmptyClientID = errors.New("ClientID parameter is required")

// ErrNoTranslatorData error used if passed nil TranslatorData
var ErrNoTranslatorData = errors.New("passed nil TranslatorData")

// TranslatorService implements gRPC service
type TranslatorService struct {
	data    *common.TranslatorData
	logger  *logrus.Entry
	service common.ITranslatorService
	UnimplementedReaderServer
	UnimplementedReaderSymServer
	UnimplementedTokenizatorServer
	UnimplementedSearchableEncryptionServer
	UnimplementedWriterServer
	UnimplementedWriterSymServer
}

// NewTranslatorService return new TranslatorService instance
func NewTranslatorService(service common.ITranslatorService, translatorData *common.TranslatorData) (*TranslatorService, error) {
	logger := logrus.WithField("service", "grpc_service")
	if translatorData == nil {
		return nil, ErrNoTranslatorData
	}
	return &TranslatorService{translatorData, logger, service,
		UnimplementedReaderServer{}, UnimplementedReaderSymServer{}, UnimplementedTokenizatorServer{},
		UnimplementedSearchableEncryptionServer{}, UnimplementedWriterServer{}, UnimplementedWriterSymServer{}}, nil
}

// Errors possible during decrypting AcraStructs.
var (
	ErrCantDecrypt = errors.New("can't decrypt data")
)

// Encrypt encrypt data from gRPC request and returns AcraStruct or error.
func (service *TranslatorService) Encrypt(ctx context.Context, request *EncryptRequest) (*EncryptResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Encrypt"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Encrypt"}).Debugln("End processing request")

	response, err := service.service.Encrypt(ctx, request.Data, request.ClientId, nil)
	if err != nil {
		base.APIEncryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := "Unexpected error with AcraStruct generation"
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantEncryptData).Warningln(msg)
		return nil, err
	}
	return &EncryptResponse{Acrastruct: response}, nil
}

// Decrypt decrypts AcraStruct from gRPC request and returns decrypted data or error.
func (service *TranslatorService) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Decrypt"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Decrypt"}).Debugln("End processing request")

	response, err := service.service.Decrypt(ctx, request.Acrastruct, request.ClientId, nil)
	if err != nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).WithError(err).Errorln("Can't decrypt AcraStruct")
		return nil, err
	}
	return &DecryptResponse{Data: response}, nil
}

// EncryptSearchable encrypt data with AcraStruct and calculate hash for searching
func (service *TranslatorService) EncryptSearchable(ctx context.Context, request *SearchableEncryptionRequest) (*SearchableEncryptionResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Encrypt (searchable)"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Encrypt (searchable)"}).Debugln("End processing request")

	response, err := service.service.EncryptSearchable(ctx, request.Data, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't create AcraStruct")
		return nil, err
	}

	return &SearchableEncryptionResponse{Hash: response.Hash, Acrastruct: response.EncryptedData}, nil
}

// DecryptSearchable decrypt AcraStruct and verify hash
func (service *TranslatorService) DecryptSearchable(ctx context.Context, request *SearchableDecryptionRequest) (*SearchableDecryptionResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Decrypt (searchable)"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Decrypt (searchable)"}).Debugln("End processing request")

	response, err := service.service.DecryptSearchable(ctx, request.Data, request.Hash, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't decrypt AcraStruct")
		return nil, err
	}
	return &SearchableDecryptionResponse{Data: response}, nil
}

// GenerateQueryHash generates searchable hash for data
func (service *TranslatorService) GenerateQueryHash(ctx context.Context, request *QueryHashRequest) (*QueryHashResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "GenerateQueryHash"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "GenerateQueryHash"}).Debugln("End processing request")

	response, err := service.service.GenerateQueryHash(ctx, request.Data, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't generate hash")
		return nil, err
	}
	return &QueryHashResponse{Hash: response}, nil
}

// Tokenize data from request
func (service *TranslatorService) Tokenize(ctx context.Context, request *TokenizeRequest) (*TokenizeResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Tokenize"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Tokenize"}).Debugln("End processing request")

	var data interface{}
	var tokenType tokenCommon.TokenType
	switch val := request.GetValue().(type) {
	case *TokenizeRequest_BytesValue:
		data = val.BytesValue
		tokenType = tokenCommon.TokenType_Bytes
	case *TokenizeRequest_EmailValue:
		data = tokenCommon.Email(val.EmailValue)
		tokenType = tokenCommon.TokenType_Email
	case *TokenizeRequest_Int32Value:
		data = val.Int32Value
		tokenType = tokenCommon.TokenType_Int32
	case *TokenizeRequest_Int64Value:
		data = val.Int64Value
		tokenType = tokenCommon.TokenType_Int64
	case *TokenizeRequest_StrValue:
		data = val.StrValue
		tokenType = tokenCommon.TokenType_String
	default:
		logger.Errorln("Unsupported token type")
		return nil, errors.New("unsupported value type")
	}

	response, err := service.service.Tokenize(ctx, data, tokenType, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't tokenize data")
		return nil, err
	}
	switch val := response.(type) {
	case []byte:
		return &TokenizeResponse{Response: &TokenizeResponse_BytesToken{BytesToken: val}}, nil
	case int32:
		return &TokenizeResponse{Response: &TokenizeResponse_Int32Token{Int32Token: val}}, nil
	case int64:
		return &TokenizeResponse{Response: &TokenizeResponse_Int64Token{Int64Token: val}}, nil
	case string:
		return &TokenizeResponse{Response: &TokenizeResponse_StrToken{StrToken: val}}, nil
	case tokenCommon.Email:
		return &TokenizeResponse{Response: &TokenizeResponse_EmailToken{EmailToken: string(val)}}, nil
	default:
		logger.Errorln("Unsupported token type")
		return nil, errors.New("unsupported value type")
	}
}

// Detokenize data from request
func (service *TranslatorService) Detokenize(ctx context.Context, request *TokenizeRequest) (*TokenizeResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Detokenize"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "Detokenize"}).Debugln("End processing request to detokenize token")

	var data interface{}
	var tokenType tokenCommon.TokenType
	switch val := request.GetValue().(type) {
	case *TokenizeRequest_BytesValue:
		data = val.BytesValue
		tokenType = tokenCommon.TokenType_Bytes
	case *TokenizeRequest_EmailValue:
		data = tokenCommon.Email(val.EmailValue)
		tokenType = tokenCommon.TokenType_Email
	case *TokenizeRequest_Int32Value:
		data = val.Int32Value
		tokenType = tokenCommon.TokenType_Int32
	case *TokenizeRequest_Int64Value:
		data = val.Int64Value
		tokenType = tokenCommon.TokenType_Int64
	case *TokenizeRequest_StrValue:
		data = val.StrValue
		tokenType = tokenCommon.TokenType_String
	default:
		logger.Errorln("Unsupported token type")
		return nil, errors.New("unsupported value type")
	}

	response, err := service.service.Detokenize(ctx, data, tokenType, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't detokenize data")
		return nil, err
	}
	switch val := response.(type) {
	case []byte:
		return &TokenizeResponse{Response: &TokenizeResponse_BytesToken{BytesToken: val}}, nil
	case int32:
		return &TokenizeResponse{Response: &TokenizeResponse_Int32Token{Int32Token: val}}, nil
	case int64:
		return &TokenizeResponse{Response: &TokenizeResponse_Int64Token{Int64Token: val}}, nil
	case string:
		return &TokenizeResponse{Response: &TokenizeResponse_StrToken{StrToken: val}}, nil
	case tokenCommon.Email:
		return &TokenizeResponse{Response: &TokenizeResponse_EmailToken{EmailToken: string(val)}}, nil
	default:
		logger.Errorln("Unsupported token type")
		return nil, errors.New("unsupported value type")
	}
}

// Errors related with gRPC requests
var (
	ErrKeysNotFound     = errors.New("keys not found")
	ErrEncryptionFailed = errors.New("encryption failed")
)

// EncryptSymSearchable encrypts data using AcraBlock and calculate searchable hash
func (service *TranslatorService) EncryptSymSearchable(ctx context.Context, request *SearchableSymEncryptionRequest) (*SearchableSymEncryptionResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "EncryptSym (searchable)"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "EncryptSym (searchable)"}).Debugln("End processing request")
	if request.ClientId == nil {
		logger.Errorln("Empty ClientID")
		return nil, ErrEmptyClientID
	}
	logger.Debugln("Load encryption symmetric key from KeyStore")
	symKey, err := service.data.Keystorage.GetClientIDSymmetricKey(request.ClientId)
	if err != nil {
		logger.WithError(err).Errorln("Can't load symmetric keys")
		return nil, ErrKeysNotFound
	}

	logger.Debugln("Load secret key for HMAC from KeyStore")
	hmacKey, err := service.data.Keystorage.GetHMACSecretKey(request.ClientId)
	if err != nil {
		logger.WithError(err).Errorln("Can't load HMAC key")
		return nil, ErrKeysNotFound
	}
	logger.Debugln("Generate HMAC")
	dataHash := hmac.GenerateHMAC(hmacKey, request.Data)
	logger.Debugln("Create AcraBlock")
	acrastruct, err := acrablock.CreateAcraBlock(request.Data, symKey, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't create AcraBlock")
		return nil, ErrEncryptionFailed
	}
	return &SearchableSymEncryptionResponse{Hash: dataHash, Acrablock: acrastruct}, nil
}

// DecryptSymSearchable AcraBlock and verify hash
func (service *TranslatorService) DecryptSymSearchable(ctx context.Context, request *SearchableSymDecryptionRequest) (*SearchableSymDecryptionResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "DecryptSym (searchable)"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "DecryptSym (searchable)"}).Debugln("End processing request")
	if request.ClientId == nil {
		logger.Errorln("Empty ClientID")
		return nil, ErrEmptyClientID
	}

	decrypted, err := service.service.DecryptSymSearchable(ctx, request.Data, request.Hash, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't decrypt searchable AcraBlock")
		return nil, ErrCantDecrypt
	}

	return &SearchableSymDecryptionResponse{Data: decrypted}, nil
}

// EncryptSym encrypts data using AcraBlock
func (service *TranslatorService) EncryptSym(ctx context.Context, request *EncryptSymRequest) (*EncryptSymResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "EncryptSym"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "EncryptSym"}).Debugln("End processing request")
	response, err := service.service.EncryptSym(ctx, request.Data, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't create AcraBlock")
		return nil, err
	}

	return &EncryptSymResponse{Acrablock: response}, nil
}

// DecryptSym decrypts AcraBlock
func (service *TranslatorService) DecryptSym(ctx context.Context, request *DecryptSymRequest) (*DecryptSymResponse, error) {
	logger := service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "DecryptSym"})
	logger.Debugln("New request")
	defer logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "operation": "DecryptSym"}).Debugln("End processing request")
	response, err := service.service.DecryptSym(ctx, request.Acrablock, request.ClientId, nil)
	if err != nil {
		logger.WithError(err).Errorln("Can't create AcraStruct")
		return nil, err
	}
	return &DecryptSymResponse{Data: response}, nil
}
