package crypto

import (
	"context"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
)

// DecryptHandler implements EnvelopeCallbackHandler as EnvelopeDetector callback for simple decryption processing
type DecryptHandler struct {
	processor base.DataProcessor
	keyStore  keystore.DataEncryptorKeyStore
}

// NewDecryptHandler construct new DecryptHandler with keystore and DataProcessor
func NewDecryptHandler(keyStore keystore.DataEncryptorKeyStore, processor base.DataProcessor) DecryptHandler {
	return DecryptHandler{
		keyStore:  keyStore,
		processor: processor,
	}
}

// OnCryptoEnvelope implementation of EnvelopeCallbackHandler for decryption processing
func (d DecryptHandler) OnCryptoEnvelope(ctx context.Context, container []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)

	decrypted, err := d.processor.Process(container, &base.DataProcessorContext{
		Keystore: d.keyStore,
		Context:  ctx,
	})

	if err != nil {
		accessContext := base.AccessContextFromContext(ctx)
		logger.WithFields(log.Fields{
			logging.FieldKeyEventCode: logging.EventCodeErrorDecryptorCantDecryptBinary,
			"client_id":               string(accessContext.GetClientID()),
			"zone_id":                 string(accessContext.GetZoneID()),
		}).WithError(err).Warningln("Can't decrypt SerializedContainer")
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()

		// if old container matched deserialize to return as is
		if base.IsOldContainerFromContext(ctx) {
			oldContainer, _, err := DeserializeEncryptedData(container)
			if err != nil {
				logger.WithError(err).Warningln("Can't deserialize SerializedContainer")
				return nil, err
			}
			return oldContainer, nil
		}

		return container, nil
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	return decrypted, nil
}

// ID return string representation of DecryptHandler
func (d DecryptHandler) ID() string {
	return "DecryptHandler"
}
