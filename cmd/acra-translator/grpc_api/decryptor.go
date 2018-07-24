package grpc_api

import (
	"golang.org/x/net/context"

	"errors"
	"github.com/cossacklabs/acra/cmd/acra-translator/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/sirupsen/logrus"
)

type DecryptGRPCService struct {
	*common.TranslatorData
}

func NewDecryptGRPCService(data *common.TranslatorData) (*DecryptGRPCService, error) {
	return &DecryptGRPCService{TranslatorData: data}, nil
}

var ErrCantDecrypt = errors.New("can't decrypt data")
var ErrClientIdRequired = errors.New("ClientId is empty")

func (service *DecryptGRPCService) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	var privateKey *keys.PrivateKey
	var err error
	var decryptionContext []byte = nil
	logger := logrus.WithFields(logrus.Fields{"client_id": string(request.ClientId), "zone_id": string(request.ZoneId), "translator": "grpc"})
	if len(request.ClientId) == 0 {
		logrus.Errorln("Grpc request without ClientId not allowed")
		return nil, ErrClientIdRequired
	}
	if len(request.ZoneId) != 0 {
		privateKey, err = service.TranslatorData.Keystorage.GetZonePrivateKey(request.ZoneId)
		decryptionContext = request.ZoneId
	} else {
		privateKey, err = service.TranslatorData.Keystorage.GetServerDecryptionPrivateKey(request.ClientId)
	}
	if err != nil {
		logger.WithError(err).Errorln("Can't load private key for decryption")
		return nil, ErrCantDecrypt
	}
	data, decryptErr := base.DecryptAcrastruct(request.Acrastruct, privateKey, decryptionContext)
	utils.FillSlice(byte(0), privateKey.Value)
	if decryptErr != nil {
		logger.WithError(decryptErr).Errorln("Can't decrypt AcraStruct")
		if service.TranslatorData.CheckPoisonRecords {
			poisoned, err := base.CheckPoisonRecord(request.Acrastruct, service.TranslatorData.Keystorage)
			if err != nil {
				logger.WithError(err).Errorln("Can't check for poison record, possible missing Poison record decryption key")
				return nil, ErrCantDecrypt
			}
			if poisoned {
				logger.Errorln("Recognized poison record")
				if service.TranslatorData.PoisonRecordCallbacks.HasCallbacks() {
					if err := service.TranslatorData.PoisonRecordCallbacks.Call(); err != nil {
						logger.WithError(err).Errorln("Unexpected error on poison record's callbacks")
					}
				}
				return nil, ErrCantDecrypt
			}
		}
		return nil, ErrCantDecrypt
	}
	return &DecryptResponse{Data: data}, nil
}
