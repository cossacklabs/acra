package crypto

import (
	"github.com/cossacklabs/acra/encryptor/config"
)

// EncryptHandler wraps RegistryHandler as standalone CryptoEnvelope encryptor
type EncryptHandler struct {
	handler RegistryHandler
}

// NewEncryptHandler construct new EncryptHandler for CryptoEnvelopeType with RegistryHandler
func NewEncryptHandler(handler RegistryHandler) EncryptHandler {
	return EncryptHandler{
		handler: handler,
	}
}

// EncryptWithClientID implementation of ContainerHandler.EncryptWithClientID method
func (r EncryptHandler) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if !setting.OnlyEncryption() {
		return data, nil
	}

	return r.handler.EncryptWithClientID(clientID, data, setting)
}

// EncryptWithZoneID implementation of ContainerHandler.EncryptWithZoneID method
func (r EncryptHandler) EncryptWithZoneID(zoneID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if !setting.OnlyEncryption() {
		return data, nil
	}

	return r.handler.EncryptWithZoneID(zoneID, data, setting)
}
