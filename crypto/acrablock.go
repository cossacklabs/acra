package crypto

import (
	"errors"
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// AcraBlockEnvelopeID represent AcraBlock EnvelopeID will be serialized inside CryptoContainer
const AcraBlockEnvelopeID = 0xF0

// AcraBlockHandler AcraBlock implementation of ContainerHandler interface
type AcraBlockHandler struct{}

// ErrEmptyZoneInContext describes nil zone in context error
var ErrEmptyZoneInContext = errors.New("nil zone in context")

// NewAcraBlockHandler construct new AcraBlockHandler with keystore
func NewAcraBlockHandler() ContainerHandler {
	return AcraBlockHandler{}
}

// Name implementation of ContainerHandler method
func (handler AcraBlockHandler) Name() string {
	return string(config.CryptoEnvelopeTypeAcraBlock)
}

// ID implementation of ContainerHandler method
func (handler AcraBlockHandler) ID() byte {
	return AcraBlockEnvelopeID
}

// MatchDataSignature implementation of ContainerHandler method
func (handler AcraBlockHandler) MatchDataSignature(bytes []byte) bool {
	_, _, err := acrablock.ExtractAcraBlockFromData(bytes)
	return err == nil
}

// Decrypt implementation of ContainerHandler method
func (handler AcraBlockHandler) Decrypt(data []byte, context *base.DataProcessorContext) ([]byte, error) {
	logrus.Debugln("Process: Decrypt AcraBlock")
	acraBlock, err := acrablock.NewAcraBlockFromData(data)
	if err != nil {
		logrus.WithError(err).Debugln("AcraBlockHandler.Process: AcraBlock not found, exit")
		return data, err
	}
	var privateKeys [][]byte
	accessContext := base.AccessContextFromContext(context.Context)
	var zoneID []byte
	if accessContext.IsWithZone() {
		// skip if not matched by previous processor
		if accessContext.GetZoneID() == nil {
			return data, ErrEmptyZoneInContext
		}
		privateKeys, err = context.Keystore.GetZoneIDSymmetricKeys(accessContext.GetZoneID())
		zoneID = accessContext.GetZoneID()
	} else {
		privateKeys, err = context.Keystore.GetClientIDSymmetricKeys(accessContext.GetClientID())
		zoneID = nil
	}
	defer utils.ZeroizeSymmetricKeys(privateKeys)
	if err != nil {
		logging.GetLoggerFromContext(context.Context).WithError(err).WithFields(
			logrus.Fields{"client_id": string(accessContext.GetClientID()), "zone_id": string(accessContext.GetZoneID())}).Warningln("Can't read private key for matched client_id/zone_id")
		return []byte{}, err
	}
	decrypted, err := acraBlock.Decrypt(privateKeys, zoneID)
	if err != nil {
		logging.GetLoggerFromContext(context.Context).WithError(err).Errorln("Can't decrypt AcraBlock")
		return nil, ErrDecryptionError
	}
	logrus.WithField("context", string(zoneID)).Debugln("Decrypted Acrablock")
	return decrypted, nil
}

// EncryptWithClientID implementation of ContainerHandler method
func (handler AcraBlockHandler) EncryptWithClientID(clientID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error) {
	// skip already encrypted AcraBlock
	if _, _, err := acrablock.ExtractAcraBlockFromData(data); err == nil {
		return data, nil
	}

	keys, err := context.Keystore.GetClientIDSymmetricKeys(clientID)
	if err != nil {
		logrus.WithError(err).WithField("client_id", clientID).WithField("handler", handler.Name()).Warningln("Can't read private key for matched client_id")
		return data, err
	}
	defer utils.ZeroizeSymmetricKeys(keys)

	if len(keys) == 0 {
		return data, keystore.ErrKeysNotFound
	}
	return acrablock.CreateAcraBlock(data, keys[0], nil)
}

// EncryptWithZoneID implementation of ContainerHandler method
func (handler AcraBlockHandler) EncryptWithZoneID(zoneID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error) {
	if _, _, err := acrablock.ExtractAcraBlockFromData(data); err == nil {
		return data, nil
	}

	keys, err := context.Keystore.GetZoneIDSymmetricKeys(zoneID)
	if err != nil {
		logrus.WithError(err).WithField("zone_id", zoneID).WithField("handler", handler.Name()).Warningln("Can't read private key for matched zone_id")
		return data, err
	}
	defer utils.ZeroizeSymmetricKeys(keys)

	if len(keys) == 0 {
		return data, keystore.ErrKeysNotFound
	}
	return acrablock.CreateAcraBlock(data, keys[0], zoneID)
}
