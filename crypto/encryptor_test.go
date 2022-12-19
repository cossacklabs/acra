package crypto

import (
	"bytes"
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/themis/gothemis/keys"
	"testing"
)

func TestEncryptHandler(t *testing.T) {
	err := InitRegistry(nil)
	if err != nil {
		t.Fatal("failed to initialize registry - ", err)
	}

	clientID := []byte("user0")

	keystore := &mocks.ServerKeyStore{}

	registryHandler := NewRegistryHandler(keystore)
	encryptor := NewEncryptHandler(registryHandler)

	rawData := "data_to_encrypt"

	acraBlockEnvelopeType := config.CryptoEnvelopeTypeAcraBlock
	acraStructEnvelopeType := config.CryptoEnvelopeTypeAcraStruct

	t.Run("Encryption with ClientID", func(t *testing.T) {
		keypair, err := keys.New(keys.TypeEC)
		if err != nil {
			t.Fatal(err)
		}

		keystore.On("GetClientIDEncryptionPublicKey", clientID).Return(
			func([]byte) *keys.PublicKey {
				return keypair.Public
			},
			nil)
		keystore.On("GetClientIDSymmetricKeys", clientID).Return([][]byte{[]byte(`some key`)}, nil)
		keystore.On("GetClientIDSymmetricKey", clientID).Return([]byte(`some key`), nil)

		t.Run("AcraStruct encryption success", func(t *testing.T) {
			result, err := encryptor.EncryptWithClientID(clientID, []byte(rawData), &config.BasicColumnEncryptionSetting{
				CryptoEnvelope: &acraStructEnvelopeType,
			})
			if err != nil {
				t.Fatal("failure on encryption with clientID ", err)
			}

			internal, envelopeID, err := DeserializeEncryptedData(result)
			if err != nil {
				t.Fatal("invalid serialized container", err)
			}

			if envelopeID != AcraStructEnvelopeID {
				t.Fatal("unexpected envelopeID should be AcraStructEnvelopeID")
			}

			decrypted, err := acrastruct.DecryptAcrastruct(internal, keypair.Private, nil)
			if err != nil {
				t.Fatal("failed to Decrypt internal container", err)
			}

			if !bytes.Equal(decrypted, []byte(rawData)) {
				t.Fatal("decrypted data is not equals to internal container data")
			}
		})

		t.Run("AcraBlock encryption success", func(t *testing.T) {
			result, err := encryptor.EncryptWithClientID(clientID, []byte(rawData), &config.BasicColumnEncryptionSetting{
				CryptoEnvelope: &acraBlockEnvelopeType,
			})
			if err != nil {
				t.Fatal("failure on encryption with clientID ", err)
			}

			internal, envelopeID, err := DeserializeEncryptedData(result)
			if err != nil {
				t.Fatal("invalid serialized container", err)
			}

			if envelopeID != AcraBlockEnvelopeID {
				t.Fatal("unexpected envelopeID should be AcraStructEnvelopeID")
			}

			acraBlock, err := acrablock.NewAcraBlockFromData(internal)
			if err != nil {
				t.Fatal("failed to create acraBlock from internal container", err)
			}

			decrypted, err := acraBlock.Decrypt([][]byte{[]byte(`some key`)}, nil)
			if err != nil {
				t.Fatal("failed to Decrypt internal container", err)
			}
			if !bytes.Equal(decrypted, []byte(rawData)) {
				t.Fatal("decrypted data is not equals to internal container data")
			}
		})
	})

	t.Run("MatchSignature exit test", func(t *testing.T) {
		t.Run("MatchSignature AcraStruct exit", func(t *testing.T) {
			keypair, err := keys.New(keys.TypeEC)
			if err != nil {
				t.Fatal(err)
			}

			rawAcraStruct, err := acrastruct.CreateAcrastruct([]byte("data"), keypair.Public, nil)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("MatchSignature raw AcraStruct", func(t *testing.T) {
				encrypted, err := encryptor.EncryptWithClientID(clientID, rawAcraStruct, &config.BasicColumnEncryptionSetting{
					CryptoEnvelope: &acraStructEnvelopeType,
				})
				if err != nil {
					t.Fatal("failure on encryption with clientID ", err)
				}

				if !bytes.Equal(encrypted, rawAcraStruct) {
					t.Fatal("encrypted data should be the same as raw AcraStruct")
				}
			})

			t.Run("MatchSignature serialized AcraStruct", func(t *testing.T) {
				serializedAcraStruct, err := SerializeEncryptedData(rawAcraStruct, AcraStructEnvelopeID)
				if err != nil {
					t.Fatal("failed to serialize AcraStruct", err)
				}

				encrypted, err := encryptor.EncryptWithClientID(clientID, serializedAcraStruct, &config.BasicColumnEncryptionSetting{
					CryptoEnvelope: &acraStructEnvelopeType,
				})
				if err != nil {
					t.Fatal("failure on encryption with clientID ", err)
				}

				if !bytes.Equal(encrypted, serializedAcraStruct) {
					t.Fatal("encrypted data should be the same as raw AcraStruct")
				}
			})
		})

		t.Run("MatchSignature AcraBlock exit", func(t *testing.T) {
			rawAcraBlock, err := acrablock.CreateAcraBlock([]byte("data"), []byte(`key`), nil)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("MatchSignature raw AcraBlock", func(t *testing.T) {
				encrypted, err := encryptor.EncryptWithClientID(clientID, rawAcraBlock, &config.BasicColumnEncryptionSetting{
					CryptoEnvelope: &acraBlockEnvelopeType,
				})
				if err != nil {
					t.Fatal("failure on encryption with clientID ", err)
				}

				if !bytes.Equal(encrypted, rawAcraBlock) {
					t.Fatal("encrypted data should be the same as raw AcraStruct")
				}
			})

			t.Run("MatchSignature serialized AcraStruct", func(t *testing.T) {
				serializedAcraBlock, err := SerializeEncryptedData(rawAcraBlock, AcraBlockEnvelopeID)
				if err != nil {
					t.Fatal("failed to serialize AcraStruct", err)
				}

				encrypted, err := encryptor.EncryptWithClientID(clientID, serializedAcraBlock, &config.BasicColumnEncryptionSetting{
					CryptoEnvelope: &acraBlockEnvelopeType,
				})
				if err != nil {
					t.Fatal("failure on encryption with clientID ", err)
				}

				if !bytes.Equal(encrypted, serializedAcraBlock) {
					t.Fatal("encrypted data should be the same as raw AcraStruct")
				}
			})
		})
	})
}
