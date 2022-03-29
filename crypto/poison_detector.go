package crypto

import (
	"context"
	"errors"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// PoisonRecordDetector implements EnvelopeCallbackHandler as EnvelopeDetector callback for detection of poison records
type PoisonRecordDetector struct {
	processor base.DataProcessor

	keyStore  keystore.RecordProcessorKeyStore
	callbacks base.PoisonRecordCallbackStorage
}

// NewPoisonRecordsRecognizer construct new PoisonRecordDetector
func NewPoisonRecordsRecognizer(keyStore keystore.RecordProcessorKeyStore, processor base.DataProcessor) PoisonRecordDetector {
	return PoisonRecordDetector{
		keyStore:  keyStore,
		processor: processor,
	}
}

// SetPoisonRecordCallbacks adds PoisonRecordCallbackStorage
func (recognizer *PoisonRecordDetector) SetPoisonRecordCallbacks(callbacks base.PoisonRecordCallbackStorage) {
	recognizer.callbacks = callbacks
}

// OnCryptoEnvelope implementation of EnvelopeCallbackHandler for poison records detections
func (recognizer PoisonRecordDetector) OnCryptoEnvelope(ctx context.Context, container []byte) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Debugln("Searching for poison records")

	if !recognizer.callbacks.HasCallbacks() {
		logger.Debugln("Skip poison record check due to empty callbacks")
		return container, nil
	}
	// poison records encrypted without context parameter for SecureCell and should be used without zone mode
	// additionally will be used keystore that ignores ClientID/ZoneID and always returns poison keys
	// so no matter what clientID/zoneID we pass
	poisonCtx := base.SetAccessContextToContext(ctx, base.NewAccessContext())
	_, err := recognizer.processor.Process(container, &base.DataProcessorContext{
		Keystore: NewPoisonRecordKeyStoreWrapper(recognizer.keyStore),
		Context:  poisonCtx,
	})

	if errors.Is(err, keystore.ErrKeysNotFound) {
		logger.Warningln("Skip poison record check due to a lack of poison keys")
		return container, nil
	}

	if err == nil {
		logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorRecognizedPoisonRecord).Warningln("Recognized poison record")
		if recognizer.callbacks.HasCallbacks() {
			err = recognizer.callbacks.Call()
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantCheckPoisonRecord).WithError(err).Errorln("Unexpected error in poison record callbacks")
			}
			logger.Debugln("Processed all callbacks on poison record")
			return container, err
		}
	}
	return container, nil
}

// ID return string representation of PoisonRecordDetector
func (recognizer PoisonRecordDetector) ID() string {
	return "PoisonRecordDetector"
}

// PoisonRecordKeyStoreWrapper is wrapper of keystore.PrivateKeyStore
// UnderTheHood goal is to escape duplication of code for processing data as for simple decryption and for poison record processing
// so that, to reuse common behaviour but with different decryption keys we need to use keystore.RecordProcessorKeyStore methods as keystore.PrivateKeyStore
// because keystore.PrivateKeyStore is used inside base.DataProcessorContext which is required parameter for ContainerHandler.Process method
type PoisonRecordKeyStoreWrapper struct {
	keyStore keystore.RecordProcessorKeyStore
}

// NewPoisonRecordKeyStoreWrapper construct new PoisonRecordKeyStoreWrapper
func NewPoisonRecordKeyStoreWrapper(keyStore keystore.RecordProcessorKeyStore) keystore.DataEncryptorKeyStore {
	return PoisonRecordKeyStoreWrapper{
		keyStore: keyStore,
	}
}

// GetClientIDSymmetricKeys implementation of keystore.PrivateKeyStore for poison records keys
func (p PoisonRecordKeyStoreWrapper) GetClientIDSymmetricKeys([]byte) ([][]byte, error) {
	return p.keyStore.GetPoisonSymmetricKeys()
}

// GetClientIDSymmetricKey implementation of keystore.PrivateKeyStore for poison records symmetric key
func (p PoisonRecordKeyStoreWrapper) GetClientIDSymmetricKey([]byte) ([]byte, error) {
	return p.keyStore.GetPoisonSymmetricKey()
}

// GetServerDecryptionPrivateKeys implementation of keystore.PrivateKeyStore ith for poison records keys
func (p PoisonRecordKeyStoreWrapper) GetServerDecryptionPrivateKeys([]byte) ([]*keys.PrivateKey, error) {
	return p.keyStore.GetPoisonPrivateKeys()
}

// GetZoneIDSymmetricKeys implementation of keystore.PrivateKeyStore for poison records keys
func (p PoisonRecordKeyStoreWrapper) GetZoneIDSymmetricKeys(id []byte) ([][]byte, error) {
	return p.keyStore.GetPoisonSymmetricKeys()
}

// GetZoneIDSymmetricKey implementation of keystore.PrivateKeyStore for poison records symmetric key
func (p PoisonRecordKeyStoreWrapper) GetZoneIDSymmetricKey(id []byte) ([]byte, error) {
	return p.keyStore.GetPoisonSymmetricKey()
}

// GetZonePrivateKeys implementation of keystore.PrivateKeyStore for poison records keys
func (p PoisonRecordKeyStoreWrapper) GetZonePrivateKeys(id []byte) ([]*keys.PrivateKey, error) {
	return p.keyStore.GetPoisonPrivateKeys()
}

// HasZonePrivateKey stub implementation of keystore.PrivateKeyStore
func (p PoisonRecordKeyStoreWrapper) HasZonePrivateKey(id []byte) bool {
	panic("implement me")
}

// GetZonePrivateKey stub implementation of keystore.PrivateKeyStore
func (p PoisonRecordKeyStoreWrapper) GetZonePrivateKey(id []byte) (*keys.PrivateKey, error) {
	panic("implement me")
}

// GetServerDecryptionPrivateKey stub implementation of keystore.PrivateKeyStore
func (p PoisonRecordKeyStoreWrapper) GetServerDecryptionPrivateKey(id []byte) (*keys.PrivateKey, error) {
	panic("implement me")
}

// GetZonePublicKey stub implementation of keystore.PrivateKeyStore
func (p PoisonRecordKeyStoreWrapper) GetZonePublicKey(zoneID []byte) (*keys.PublicKey, error) {
	panic("implement me")
}

// GetClientIDEncryptionPublicKey stub implementation of keystore.PrivateKeyStore
func (p PoisonRecordKeyStoreWrapper) GetClientIDEncryptionPublicKey(clientID []byte) (*keys.PublicKey, error) {
	panic("implement me")
}
