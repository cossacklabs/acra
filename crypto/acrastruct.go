package crypto

import (
	"fmt"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/keys"

	"github.com/sirupsen/logrus"
)

// AcraStructEnvelopeID represent AcraBlock EnvelopeID will be serialized inside CryptoContainer
const AcraStructEnvelopeID = 0xF1

// AcraStructHandler AcraStruct implementation of ContainerHandler interface
type AcraStructHandler struct {
}

// NewAcraStructHandler construct new AcraStructHandler with keystore
func NewAcraStructHandler() ContainerHandler {
	return AcraStructHandler{}
}

// Name implementation of ContainerHandler method
func (handler AcraStructHandler) Name() string {
	return string(config.CryptoEnvelopeTypeAcraStruct)
}

// ID implementation of ContainerHandler method
func (handler AcraStructHandler) ID() byte {
	return AcraStructEnvelopeID
}

// MatchDataSignature implementation of ContainerHandler method
func (handler AcraStructHandler) MatchDataSignature(bytes []byte) bool {
	return acrastruct.ValidateAcraStructLength(bytes) == nil
}

// Decrypt implementation of ContainerHandler method
func (handler AcraStructHandler) Decrypt(data []byte, context *base.DataProcessorContext) ([]byte, error) {
	logger := logging.GetLoggerFromContext(context.Context).WithField("handler", handler.Name())
	if err := acrastruct.ValidateAcraStructLength(data); err != nil {
		logger.WithError(err).Debugln("AcraStructHandler.Process: AcraStruct not found, exit")
		return data, err
	}

	var privateKeys []*keys.PrivateKey
	var err error
	accessContext := base.AccessContextFromContext(context.Context)
	var zoneID []byte

	if accessContext.IsWithZone() {
		privateKeys, err = context.Keystore.GetZonePrivateKeys(accessContext.GetZoneID())
		zoneID = accessContext.GetZoneID()
	} else {
		privateKeys, err = context.Keystore.GetServerDecryptionPrivateKeys(accessContext.GetClientID())
	}
	defer utils.ZeroizePrivateKeys(privateKeys)
	if err != nil {
		logger.WithError(err).WithFields(
			logrus.Fields{
				logging.FieldKeyEventCode: logging.EventCodeErrorCantReadKeys,
				"client_id":               string(accessContext.GetClientID()),
				"zone_id":                 string(accessContext.GetZoneID()),
			}).
			Debugln("The error occurred due to one of the following reasons: 1. The client_id from TLS certificate doesn't match the encryption key: check that you are using the appropriate TLS certificate or configure acra-server with a different --client_id=<client_id>. 2. The encryption key for the client_id from TLS certificate is missing, generate encryption keys using keymaker utility for your TLS certificate (or with specified client_id); 3. The required keys are missing in the `keys_dir`, ensure that `keys_dir` param is pointed to a folder with keys or to the correct Redis database's number")
		return []byte{}, fmt.Errorf("can't read private key for matched client_id/zone_id to decrypt AcraStruct: %w", err)
	}
	return acrastruct.DecryptRotatedAcrastruct(data, privateKeys, zoneID)
}

// EncryptWithClientID implementation of ContainerHandler method
func (handler AcraStructHandler) EncryptWithClientID(clientID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error) {
	if err := acrastruct.ValidateAcraStructLength(data); err == nil {
		return data, nil
	}
	publicKey, err := context.Keystore.GetClientIDEncryptionPublicKey(clientID)
	if err != nil {
		logrus.WithError(err).WithField("client_id", clientID).WithField("handler", handler.Name()).Warningln("Can't read private key for matched client_id")
		return nil, err
	}
	return acrastruct.CreateAcrastruct(data, publicKey, nil)

}

// EncryptWithZoneID implementation of ContainerHandler method
func (handler AcraStructHandler) EncryptWithZoneID(zoneID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error) {
	if err := acrastruct.ValidateAcraStructLength(data); err == nil {
		return data, nil
	}
	publicKey, err := context.Keystore.GetZonePublicKey(zoneID)
	if err != nil {
		logrus.WithError(err).WithField("zone_id", zoneID).WithField("handler", handler.Name()).Warningln("Can't read private key for matched zone_id")
		return nil, err
	}
	return acrastruct.CreateAcrastruct(data, publicKey, zoneID)
}
