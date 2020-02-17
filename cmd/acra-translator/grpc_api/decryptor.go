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

// Package grpc_api implements gRPC API handler: users can send AcraStructs via gRPC to AcraConnector,
// AcraConnector wraps connection via Themis SecureSession. gRPC handler parses gRPC requests, decrypts AcraStructs
// and returns plaintext data via gRPC response.
package grpc_api

import (
	"errors"
	acrawriter "github.com/cossacklabs/acra/acra-writer"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// DecryptGRPCService represents decryptor for decrypting AcraStructs from gRPC requests.
type DecryptGRPCService struct {
	*common.TranslatorData
	logger *logrus.Entry
}

// NewDecryptGRPCService creates new DecryptGRPCService.
func NewDecryptGRPCService(data *common.TranslatorData) (*DecryptGRPCService, error) {
	return &DecryptGRPCService{TranslatorData: data, logger: logrus.WithField("service", "grpc_service")}, nil
}

// Errors possible during decrypting AcraStructs.
var (
	ErrCantDecrypt      = errors.New("can't decrypt data")
	ErrClientIDRequired = errors.New("clientID is empty")
	ErrCantEncrypt      = errors.New("can't encrypt data")
)

// Encrypt encrypt data from gRPC request and returns AcraStruct or error.
func (service *DecryptGRPCService) Encrypt(ctx context.Context, request *EncryptRequest) (*EncryptResponse, error) {
	service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "zone_id": string(request.ZoneId), "operation": "Encrypt"}).Debugln("New request")
	defer service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "zone_id": string(request.ZoneId), "operation": "Encrypt"}).Debugln("End processing request")
	timer := prometheus.NewTimer(prometheus.ObserverFunc(common.RequestProcessingTimeHistogram.WithLabelValues(common.GrpcRequestType).Observe))
	defer timer.ObserveDuration()

	logger := logrus.WithFields(logrus.Fields{"client_id": string(request.ClientId), "zone_id": string(request.ZoneId), "translator": "grpc"})
	var publicKey *keys.PublicKey
	var err error
	if len(request.ZoneId) != 0 {
		publicKey, err = service.TranslatorData.Keystorage.GetZonePublicKey(request.ZoneId)
		logger.Debugln("Loaded zoneID key for encryption")
	} else {
		publicKey, err = service.TranslatorData.Keystorage.GetClientIDEncryptionPublicKey(request.ClientId)
		logger.Debugln("Loaded clientID key for encryption")
	}
	if err != nil {
		base.APIEncryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := "Invalid client or zone id"
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).Warningln(msg)
		return nil, ErrCantEncrypt
	}
	// publicKey will be clientID' if wasn't provided ZoneID and context.ZoneID will be nil, otherwise used ZoneID
	// public key and context.ZoneID will have value
	acrastruct, err := acrawriter.CreateAcrastruct(request.Data, publicKey, request.ZoneId)
	if err != nil {
		base.APIEncryptionCounter.WithLabelValues(base.EncryptionTypeFail).Inc()
		msg := "Unexpected error with AcraStruct generation"
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantEncryptData).Warningln(msg)
		return nil, ErrCantEncrypt
	}
	base.APIEncryptionCounter.WithLabelValues(base.EncryptionTypeSuccess).Inc()
	logger.Infoln("Encrypted data to AcraStruct")
	return &EncryptResponse{Acrastruct: acrastruct}, nil
}

// Decrypt decrypts AcraStruct from gRPC request and returns decrypted data or error.
func (service *DecryptGRPCService) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "zone_id": string(request.ZoneId), "operation": "Decrypt"}).Debugln("New request")
	defer service.logger.WithFields(logrus.Fields{"client_id": string(request.ClientId), "zone_id": string(request.ZoneId), "operation": "Decrypt"}).Debugln("End processing request")
	var privateKeys []*keys.PrivateKey
	var err error
	var decryptionContext []byte

	timer := prometheus.NewTimer(prometheus.ObserverFunc(common.RequestProcessingTimeHistogram.WithLabelValues(common.GrpcRequestType).Observe))
	defer timer.ObserveDuration()

	logger := logrus.WithFields(logrus.Fields{"client_id": string(request.ClientId), "zone_id": string(request.ZoneId), "translator": "grpc"})
	if len(request.ClientId) == 0 {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorClientIDMissing).Errorln("GRPC request without ClientID not allowed")
		return nil, ErrClientIDRequired
	}
	if len(request.ZoneId) != 0 {
		privateKeys, err = service.TranslatorData.Keystorage.GetZonePrivateKeys(request.ZoneId)
		decryptionContext = request.ZoneId
	} else {
		privateKeys, err = service.TranslatorData.Keystorage.GetServerDecryptionPrivateKeys(request.ClientId)
	}
	if err != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadKeys).WithError(err).Errorln("Can't load private key for decryption")
		return nil, ErrCantDecrypt
	}
	data, decryptErr := base.DecryptRotatedAcrastruct(request.Acrastruct, privateKeys, decryptionContext)
	for _, privateKey := range privateKeys {
		utils.FillSlice(byte(0), privateKey.Value)
	}
	if decryptErr != nil {
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorTranslatorCantDecryptAcraStruct).WithError(decryptErr).Errorln("Can't decrypt AcraStruct")
		if service.TranslatorData.CheckPoisonRecords {
			poisoned, err := base.CheckPoisonRecord(request.Acrastruct, service.TranslatorData.Keystorage)
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Can't check for poison record, possible missing Poison record decryption key")
				return nil, ErrCantDecrypt
			}
			if poisoned {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Errorln("Recognized poison record")
				if service.TranslatorData.PoisonRecordCallbacks.HasCallbacks() {
					if err := service.TranslatorData.PoisonRecordCallbacks.Call(); err != nil {
						logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantHandleRecognizedPoisonRecord).WithError(err).Errorln("Unexpected error on poison record's callbacks")
					}
				}
				// don't show users that we found poison record
				return nil, ErrCantDecrypt
			}
		}
		return nil, ErrCantDecrypt
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	return &DecryptResponse{Data: data}, nil
}
