package crypto

import (
	"context"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
)

// ReEncryptHandler wraps RegistryHandler with functionality of re-encryption AcraStruct to AcraBlock
type ReEncryptHandler struct {
	handler RegistryHandler

	keystore keystore.DataEncryptorKeyStore
}

// NewReEncryptHandler construct new RegistryHandler struct with encryptor.EmptyCheckFunction as SkipEncryptionFunc
func NewReEncryptHandler(keyStore keystore.DataEncryptorKeyStore) ReEncryptHandler {
	return ReEncryptHandler{
		keystore: keyStore,
		handler:  NewRegistryHandler(keyStore),
	}
}

// EncryptWithClientID implementation of ContainerHandler.EncryptWithClientID method
func (r ReEncryptHandler) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if setting.GetCryptoEnvelope() != config.CryptoEnvelopeTypeAcraBlock || !setting.OnlyEncryption() {
		return data, nil
	}

	// case when data encrypted on app side (for example AcraStructs with AcraWriter) and should not be encrypted second time
	if r.MatchDataSignature(data) {
		return data, nil
	}

	if setting.ShouldReEncryptAcraStructToAcraBlock() {
		// decrypt AcraStruct inside SerializedContainer to encrypt it with AcraBlock
		if _, serialized, err := ExtractSerializedContainer(data); err == nil {
			dataContext := base.NewDataProcessorContext(r.keystore)
			accessContext := base.NewAccessContext(base.WithClientID(clientID))
			dataContext.Context = base.SetAccessContextToContext(context.Background(), accessContext)

			decrypted, err := r.handler.Process(serialized, dataContext)
			if err != nil {
				return data, err
			}
			data = decrypted
		}
	}

	return r.handler.EncryptWithClientID(clientID, data, setting)
}

// MatchDataSignature implementation of ContainerHandler.MatchDataSignature method
func (r ReEncryptHandler) MatchDataSignature(data []byte) bool {
	handler, err := GetHandlerByName(string(config.CryptoEnvelopeTypeAcraBlock))
	if err != nil {
		return false
	}

	if ok := handler.MatchDataSignature(data); ok {
		return true
	}

	internal, _, err := DeserializeEncryptedData(data)
	if err != nil {
		return false
	}

	return handler.MatchDataSignature(internal)
}
