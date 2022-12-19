package acrablock

import (
	"context"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
)

// standaloneEncryptorFilterFunction return true if operation should be applied only if setting configured for
// encryption without any other operations like tokenization/masking
func standaloneEncryptorFilterFunction(setting config.ColumnEncryptionSetting) bool {
	return setting.GetCryptoEnvelope() != config.CryptoEnvelopeTypeAcraBlock || !setting.OnlyEncryption()
}

// DataEncryptor that uses AcraBlocks for encryption
type DataEncryptor struct {
	keyStore               keystore.DataEncryptorKeyStore
	needSkipEncryptionFunc encryptor.CheckFunction
}

// NewDataEncryptor return new DataEncryptor that uses AcraBlock to encrypt data which may be used by other encryptors
func NewDataEncryptor(keyStore keystore.DataEncryptorKeyStore) (*DataEncryptor, error) {
	return &DataEncryptor{keyStore: keyStore, needSkipEncryptionFunc: encryptor.EmptyCheckFunction}, nil
}

// NewStandaloneDataEncryptor return new DataEncryptor that uses AcraBlock to encrypt data as separate OnColumn processor
// and checks passed setting that it configured only for transparent AcraBlock encryption
func NewStandaloneDataEncryptor(keyStore keystore.DataEncryptorKeyStore) (*DataEncryptor, error) {
	return &DataEncryptor{keyStore: keyStore, needSkipEncryptionFunc: standaloneEncryptorFilterFunction}, nil
}

// EncryptWithClientID encrypt data using AcraBlock
func (d *DataEncryptor) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	if d.needSkipEncryptionFunc(setting) {
		return data, nil
	}
	// skip already encrypted AcraBlock
	if _, _, err := ExtractAcraBlockFromData(data); err == nil {
		return data, nil
	}
	if setting.ShouldReEncryptAcraStructToAcraBlock() {
		// decrypt AcraStruct to encrypt it with AcraBlock
		if err := acrastruct.ValidateAcraStructLength(data); err == nil {
			dataContext := base.NewDataProcessorContext(d.keyStore)
			accessContext := base.NewAccessContext(base.WithClientID(clientID))
			dataContext.Context = base.SetAccessContextToContext(context.Background(), accessContext)
			decrypted, err := base.DecryptProcessor{}.Process(data, dataContext)
			if err != nil {
				return data, err
			}
			data = decrypted
		}
	}
	keys, err := d.keyStore.GetClientIDSymmetricKey(clientID)
	if err != nil {
		return data, err
	}
	return CreateAcraBlock(data, keys, nil)
}
