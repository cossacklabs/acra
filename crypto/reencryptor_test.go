package crypto

import (
	"bytes"
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/acrastruct"
	"testing"

	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestReEncryptHandler(t *testing.T) {
	err := InitRegistry(nil)
	if err != nil {
		t.Fatal("failed to initialize registry - ", err)
	}

	clientID := []byte("user0")
	zoneID := []byte("zone")

	keystore := &mocks.ServerKeyStore{}

	reEncryptor := NewReEncryptHandler(keystore)

	rawData := "data_to_encrypt"
	reEncryptToAcraBlock := true
	acraBlockEnvelopeType := config.CryptoEnvelopeTypeAcraBlock

	t.Run("Encryption with ClientID", func(t *testing.T) {
		keypair, err := keys.New(keys.TypeEC)
		if err != nil {
			t.Fatal(err)
		}

		rawAcraStruct, err := acrastruct.CreateAcrastruct([]byte(rawData), keypair.Public, nil)
		if err != nil {
			t.Fatal(err)
		}

		keystore.On("GetServerDecryptionPrivateKeys", clientID).Return([]*keys.PrivateKey{keypair.Private}, nil)
		keystore.On("GetClientIDSymmetricKeys", clientID).Return([][]byte{[]byte(`some key`)}, nil)
		keystore.On("GetClientIDSymmetricKey", clientID).Return([]byte(`some key`), nil)

		t.Run("AcraStruct reEncryption Success ", func(t *testing.T) {
			result, err := reEncryptor.EncryptWithClientID(clientID, rawAcraStruct, &config.BasicColumnEncryptionSetting{
				CryptoEnvelope:       &acraBlockEnvelopeType,
				ReEncryptToAcraBlock: &reEncryptToAcraBlock,
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

	t.Run("Encryption with ZoneID ", func(t *testing.T) {

		keypair, err := keys.New(keys.TypeEC)
		if err != nil {
			t.Fatal(err)
		}

		rawAcraStruct, err := acrastruct.CreateAcrastruct([]byte(rawData), keypair.Public, zoneID)
		if err != nil {
			t.Fatal(err)
		}
		symKey := []byte(`some key`)
		keystore.On("GetZonePrivateKeys", zoneID).Return([]*keys.PrivateKey{keypair.Private}, nil)
		keystore.On("GetZoneIDSymmetricKeys", zoneID).Return([][]byte{append([]byte{}, symKey...)}, nil)
		keystore.On("GetZoneIDSymmetricKey", zoneID).Return(append([]byte{}, symKey...), nil)

		t.Run("AcraStruct reEncryption Success ", func(t *testing.T) {
			result, err := reEncryptor.EncryptWithZoneID(zoneID, rawAcraStruct, &config.BasicColumnEncryptionSetting{
				CryptoEnvelope:       &acraBlockEnvelopeType,
				ReEncryptToAcraBlock: &reEncryptToAcraBlock,
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

			decrypted, err := acraBlock.Decrypt([][]byte{append([]byte{}, symKey...)}, zoneID)
			if err != nil {
				t.Fatal("failed to Decrypt internal container", err)
			}
			if !bytes.Equal(decrypted, []byte(rawData)) {
				t.Fatal("decrypted data is not equals to internal container data")
			}
		})
	})

	t.Run("Skip reEncryption", func(t *testing.T) {
		rawAcraBlock, err := acrablock.CreateAcraBlock([]byte("data"), []byte(`key`), nil)
		if err != nil {
			t.Fatal(err)
		}

		serialized, err := SerializeEncryptedData(rawAcraBlock, AcraBlockEnvelopeID)
		if err != nil {
			t.Fatal(err)
		}

		testData := [][]byte{rawAcraBlock, serialized}

		for _, data := range testData {
			result, err := reEncryptor.EncryptWithClientID(clientID, data, &config.BasicColumnEncryptionSetting{
				CryptoEnvelope:       &acraBlockEnvelopeType,
				ReEncryptToAcraBlock: &reEncryptToAcraBlock,
			})
			if err != nil {
				t.Fatal("failure on encryption with clientID ", err)
			}

			if !bytes.Equal(result, data) {
				t.Fatal("result data is not equal to input data")
			}
		}

	})

}
