package crypto

import (
	"fmt"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
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

	accessContext := base.AccessContextFromContext(context.Context)
	privateKeys, err := context.Keystore.GetServerDecryptionPrivateKeys(accessContext.GetClientID())
	defer utils.ZeroizePrivateKeys(privateKeys)
	if err != nil {
		logger.WithError(err).WithFields(
			logrus.Fields{
				logging.FieldKeyEventCode: logging.EventCodeErrorCantReadKeys,
				"client_id":               string(accessContext.GetClientID()),
			}).
			Debugln("Probably error occurred because: 1. used not appropriate TLS certificate or acra-server configured with inappropriate --client_id=<client_id>; 2. forgot to generate keys for your TLS certificate (or with specified client_id); 3. incorrectly configured keystore: incorrect path to folder or Redis database's number")
		return []byte{}, fmt.Errorf("can't read private key for matched client_id to decrypt AcraStruct: %w", err)
	}
	return acrastruct.DecryptRotatedAcrastruct(data, privateKeys, nil)
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
