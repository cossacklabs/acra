package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/themis/gothemis/keys"
)

func TestWrappingContainer(t *testing.T) {
	err := InitRegistry(nil)
	if err != nil {
		t.Fatal("failed to initialize registry - ", err)
	}

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}

	acraStruct, err := acrastruct.CreateAcrastruct([]byte("test-data"), keypair.Public, nil)
	if err != nil {
		t.Fatal("can't create acrastruct - ", err)
	}

	t.Run("Serialization success", func(t *testing.T) {
		serializedData, err := SerializeEncryptedData(acraStruct, AcraStructEnvelopeID)
		if err != nil {
			t.Fatal("can't serialize acrastruct - ", err)
		}

		if len(serializedData)-len(acraStruct) != SerializedContainerMinSize {
			t.Fatal("invalid serialized container format - ", err)
		}

		if !bytes.Equal(serializedData[:len(TagBegin)], TagBegin) {
			t.Fatal("invalid serialized container begin tag")
		}

		internal := serializedData[SerializedContainerMinSize:]
		if !bytes.Equal(internal, acraStruct) {
			t.Fatal("internal container does not match to the input data")
		}
	})

	t.Run("Deserialization success", func(t *testing.T) {
		serializedData, err := SerializeEncryptedData(acraStruct, AcraStructEnvelopeID)
		if err != nil {
			t.Fatal("can't serialize acrastruct - ", err)
		}

		encrypted, _, err := DeserializeEncryptedData(serializedData)
		if err != nil {
			t.Fatal("failed to deserialize data - ", err)
		}

		if !bytes.Equal(encrypted, acraStruct) {
			t.Fatal("invalid deserialized data")
		}
	})

	t.Run("Deserialization with old containers matching", func(t *testing.T) {
		encrypted, envelopeID, err := DeserializeEncryptedData(acraStruct)
		if err != nil {
			t.Fatal("failed to deserialize data - ", err)
		}

		if envelopeID != AcraStructEnvelopeID {
			t.Fatal("invalid envelopeID should be AcraStruct")
		}

		if !bytes.Equal(encrypted, acraStruct) {
			t.Fatal("invalid deserialized data")
		}
	})

	t.Run("Deserialization with invalid length field", func(t *testing.T) {
		// use double length of AcraStruct as tamper value
		length := len(acraStruct) * 2

		sumLengthBuf := [SerializedContainerLengthSize]byte{}
		binary.LittleEndian.PutUint64(sumLengthBuf[:], uint64(length))

		serialized := make([]byte, 0, length)
		serialized = append(serialized, TagBegin...)
		serialized = append(serialized, sumLengthBuf[:SerializedContainerLengthSize]...)
		serialized = append(serialized, AcraStructEnvelopeID)
		serialized = append(serialized, acraStruct...)

		_, _, err := DeserializeEncryptedData(serialized)
		if err != ErrIncorrectSerializedContainer {
			t.Fatal("failed to deserialize data - ", err)
		}
	})

	t.Run("Validation error - invalid length", func(t *testing.T) {
		_, err := validateSerializedContainer(make([]byte, 5))
		if err == nil {
			t.Fatal("validation should return not nil error")
		}

		if err != ErrIncorrectSerializedContainer {
			t.Fatal("invalid error returned")
		}
	})

	t.Run("Validation error - invalid header", func(t *testing.T) {
		serializedData, err := SerializeEncryptedData(acraStruct, 0x01)
		if err != nil {
			t.Fatal("can't serialize acrastruct - ", err)
		}

		_, err = validateSerializedContainer(serializedData)
		if err == nil {
			t.Fatal("validation should return not nil error")
		}

		if err != ErrHandlerNotFound {
			t.Fatal("invalid error returned")
		}
	})
}

func TestExtractSerializedContainer(t *testing.T) {
	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}

	err = InitRegistry(nil)
	if err != nil {
		t.Fatal("failed to initialize registry - ", err)
	}

	randomData := make([]byte, 32)
	_, err = rand.Read(randomData)
	if err != nil {
		t.Fatal(err)
	}

	acraStruct, err := acrastruct.CreateAcrastruct([]byte("test-data"), keypair.Public, nil)
	if err != nil {
		t.Fatal("can't create acrastruct - ", err)
	}

	t.Run("Serialized container extract success", func(t *testing.T) {
		rawData := append(randomData, acraStruct...)
		serializedData, err := SerializeEncryptedData(rawData, AcraStructEnvelopeID)
		if err != nil {
			t.Fatal("can't serialize acrastruct - ", err)
		}

		_, container, err := ExtractSerializedContainer(serializedData)
		if err != nil {
			t.Fatal("can't extract container - ", err)
		}

		internal, envelope, err := DeserializeEncryptedData(container)
		if err != nil {
			t.Fatal("can't deserialize container - ", err)
		}

		if envelope != AcraStructEnvelopeID {
			t.Fatal("invalid deserialized envelope - should be AcraStruct")
		}

		if !bytes.Equal(internal, rawData) {
			t.Fatal("internal container is not equal to initial")
		}
	})

	t.Run("MatchOldContainer", func(t *testing.T) {
		rawAcraBlock, err := acrablock.CreateAcraBlock([]byte("data"), []byte(`key`), nil)
		if err != nil {
			t.Fatal(err)
		}

		type testcase struct {
			Data       []byte
			envelopeID byte
		}
		testCases := []testcase{
			// AcraBlocks
			{
				Data:       rawAcraBlock,
				envelopeID: AcraBlockEnvelopeID,
			},
			// AcraStructs
			{
				Data:       acraStruct,
				envelopeID: AcraStructEnvelopeID,
			},
		}

		for _, tcase := range testCases {
			_, container, err := ExtractSerializedContainer(tcase.Data)
			if err != nil {
				t.Fatal("can't extract container - ", err)
			}

			envelopeID, err := validateSerializedContainer(container)
			if err != nil {
				t.Fatal("invalid serialized container - ", err)
			}

			if envelopeID != tcase.envelopeID {
				t.Fatal("invalid deserialized envelope - should be", tcase.envelopeID)
			}
		}
	})

	t.Run("MatchOldContainer failed", func(t *testing.T) {
		rawData := append(randomData, acraStruct...)
		_, _, err := ExtractSerializedContainer(rawData)
		if err == nil || err != ErrNoSerializedContainerExtracted {
			t.Fatal("error should be nil")
		}
	})
}

func TestDecryptWithHandler(t *testing.T) {
	err := InitRegistry(nil)
	if err != nil {
		t.Fatal("failed to initialize registry - ", err)
	}

	clientID := []byte("user0")

	randomData := make([]byte, 32)
	_, err = rand.Read(randomData)
	if err != nil {
		t.Fatal(err)
	}

	rawData := []byte("test-data")

	keystore := &mocks.ServerKeyStore{}
	registryHandler := NewRegistryHandler(keystore)

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}

	acraStruct, err := acrastruct.CreateAcrastruct(rawData, keypair.Public, nil)
	if err != nil {
		t.Fatal("can't create acrastruct - ", err)
	}

	rawAcraBlock, err := acrablock.CreateAcraBlock(rawData, []byte(`some key`), nil)
	if err != nil {
		t.Fatal("can't create acrablock - ", err)
	}

	t.Run("MatchDataSignature error", func(t *testing.T) {
		rawData := append(randomData, acraStruct...)
		serializedData, err := SerializeEncryptedData(rawData, AcraStructEnvelopeID)
		if err != nil {
			t.Fatal("can't serialize acrastruct - ", err)
		}

		handler, err := GetHandlerByEnvelopeID(AcraStructEnvelopeID)
		if err != nil {
			t.Fatal("no AcraStruct handler found - ", err)
		}

		_, err = registryHandler.DecryptWithHandler(handler, serializedData, &base.DataProcessorContext{})
		if err != ErrInvalidInternalContainer {
			t.Fatal("error should be not nil - ErrInvalidInternalContainer")
		}
	})

	t.Run("Decrypt Success", func(t *testing.T) {
		keystore.On("GetServerDecryptionPrivateKeys", clientID).Return([]*keys.PrivateKey{keypair.Private}, nil)
		keystore.On("GetClientIDSymmetricKeys", clientID).Return([][]byte{[]byte(`some key`)}, nil)

		dataContext := base.NewDataProcessorContext(keystore)
		accessContext := base.NewAccessContext(base.WithClientID(clientID))
		dataContext.Context = base.SetAccessContextToContext(context.Background(), accessContext)

		type testcase struct {
			Data       []byte
			envelopeID byte
		}
		testCases := []testcase{
			// AcraBlocks
			{
				Data:       rawAcraBlock,
				envelopeID: AcraBlockEnvelopeID,
			},
			// AcraStructs
			{
				Data:       acraStruct,
				envelopeID: AcraStructEnvelopeID,
			},
		}

		for _, tcase := range testCases {
			serializedData, err := SerializeEncryptedData(tcase.Data, tcase.envelopeID)
			if err != nil {
				t.Fatal("can't serialize data - ", err)
			}

			handler, err := GetHandlerByEnvelopeID(tcase.envelopeID)
			if err != nil {
				t.Fatal("no AcraStruct handler found - ", err)
			}

			decrypted, err := registryHandler.DecryptWithHandler(handler, serializedData, dataContext)
			if err != nil {
				t.Fatal("fail to decrypt with Handler", err)
			}

			if !bytes.Equal(decrypted, rawData) {
				t.Fatal("decrypted data is not equals to initial")
			}
		}
	})
}
