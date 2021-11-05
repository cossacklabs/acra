package crypto

import (
	"context"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
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
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantDecryptBinary).WithError(err).Warningln("Can't decrypt SerializedContainer: can't unwrap symmetric key")
		base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeFail).Inc()
		return container, nil
	}
	base.AcrastructDecryptionCounter.WithLabelValues(base.DecryptionTypeSuccess).Inc()
	return decrypted, nil
}

// ID return string representation of DecryptHandler
func (d DecryptHandler) ID() string {
	return "DecryptHandler"
}
