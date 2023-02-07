package crypto

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
)

// PrometheusContainerHandlerWrapper wraps ContainerHandler with adding prometheus metrics logic
type PrometheusContainerHandlerWrapper struct {
	ContainerHandler
	containerHandlerType string
}

// NewPrometheusContainerHandlerWrapper create new ContainerHandler prometheus wrapper
func NewPrometheusContainerHandlerWrapper(handler ContainerHandler, containerHandlerType string) PrometheusContainerHandlerWrapper {
	return PrometheusContainerHandlerWrapper{
		ContainerHandler:     handler,
		containerHandlerType: containerHandlerType,
	}
}

// Decrypt proxy ContainerHandler.Decrypt with prometheus metrics
func (handler PrometheusContainerHandlerWrapper) Decrypt(data []byte, context *base.DataProcessorContext) ([]byte, error) {
	decrypted, err := handler.ContainerHandler.Decrypt(data, context)
	if err != nil {
		base.AcraDecryptionCounter.WithLabelValues(base.LabelStatusFail, handler.containerHandlerType).Inc()
		return nil, err
	}

	base.AcraDecryptionCounter.WithLabelValues(base.LabelStatusSuccess, handler.containerHandlerType).Inc()
	return decrypted, nil
}

// EncryptWithClientID proxy ContainerHandler.EncryptWithClientID with prometheus metrics
func (handler PrometheusContainerHandlerWrapper) EncryptWithClientID(clientID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error) {
	encrypted, err := handler.ContainerHandler.EncryptWithClientID(clientID, data, context)
	if err != nil {
		base.AcraEncryptionCounter.WithLabelValues(base.LabelStatusFail, handler.containerHandlerType).Inc()
		return nil, err
	}

	base.AcraEncryptionCounter.WithLabelValues(base.LabelStatusSuccess, handler.containerHandlerType).Inc()
	return encrypted, nil
}
