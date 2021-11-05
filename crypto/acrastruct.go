package crypto

import (
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
	if err := acrastruct.ValidateAcraStructLength(data); err != nil {
		logrus.WithError(err).Debugln("AcraStructHandler.Process: AcraStruct not found, exit")
		return data, err
	}

	if context.Keystore == nil {
		return nil, ErrEmptyKeystore
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
		logging.GetLoggerFromContext(context.Context).WithError(err).WithFields(
			logrus.Fields{"client_id": string(accessContext.GetClientID()), "zone_id": string(accessContext.GetZoneID())}).Warningln("Can't read private key for matched client_id/zone_id")
		return []byte{}, err
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
