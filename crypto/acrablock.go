package crypto

import (
	"fmt"
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// AcraBlockEnvelopeID represent AcraBlock EnvelopeID will be serialized inside CryptoContainer
const AcraBlockEnvelopeID = 0xF0

// AcraBlockHandler AcraBlock implementation of ContainerHandler interface
type AcraBlockHandler struct{}

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
	logger := logging.GetLoggerFromContext(context.Context).WithField("handler", handler.Name())
	logger.Debugln("Process: Decrypt AcraBlock")
	acraBlock, err := acrablock.NewAcraBlockFromData(data)
	if err != nil {
		logger.WithError(err).Debugln("AcraBlockHandler.Process: AcraBlock not found, exit")
		return data, err
	}
	accessContext := base.AccessContextFromContext(context.Context)
	privateKeys, err := context.Keystore.GetClientIDSymmetricKeys(accessContext.GetClientID())
	defer utils.ZeroizeSymmetricKeys(privateKeys)
	if err != nil {
		logger.WithError(err).WithFields(
			logrus.Fields{
				logging.FieldKeyEventCode: logging.EventCodeErrorCantReadKeys,
				"client_id":               string(accessContext.GetClientID()),
			}).
			Debugln("Probably error occurred because: 1. used not appropriate TLS certificate or acra-server configured with inappropriate --client_id=<client_id>; 2. forgot to generate keys for your TLS certificate (or with specified client_id); 3. incorrectly configured keystore: incorrect path to folder or Redis database's number")
		return []byte{}, fmt.Errorf("can't read private key for matched client_id to decrypt AcraBlock: %w", err)
	}
	decrypted, err := acraBlock.Decrypt(privateKeys, nil)
	if err != nil {
		return nil, fmt.Errorf("can't decrypt AcraBlock: %w", ErrDecryptionError)
	}
	logger.Debugln("Decrypted AcraBlock")
	return decrypted, nil
}

// EncryptWithClientID implementation of ContainerHandler method
func (handler AcraBlockHandler) EncryptWithClientID(clientID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error) {
	// skip already encrypted AcraBlock
	if _, _, err := acrablock.ExtractAcraBlockFromData(data); err == nil {
		return data, nil
	}
	key, err := context.Keystore.GetClientIDSymmetricKey(clientID)
	if err != nil {
		return data, fmt.Errorf("can't read private key for matched client_id to encrypt with AcraBlock: %w", err)
	}
	defer utils.ZeroizeSymmetricKey(key)

	return acrablock.CreateAcraBlock(data, key, nil)
}
