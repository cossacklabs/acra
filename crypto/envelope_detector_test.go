package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore/mocks"
	"testing"

	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/themis/gothemis/keys"

	"github.com/cossacklabs/acra/acrablock"
)

func TestOldContainerDetectorWrapper(t *testing.T) {
	err := InitRegistry(nil)
	if err != nil {
		t.Fatal("failed to initialize registry - ", err)
	}

	clientID := []byte("user0")
	rawData := []byte("data")
	key := []byte("key")

	rawAcraBlock, err := acrablock.CreateAcraBlock(rawData, key, nil)
	if err != nil {
		t.Fatal(err)
	}

	keypair, err := keys.New(keys.TypeEC)
	if err != nil {
		t.Fatal(err)
	}

	rawAcraStruct, err := acrastruct.CreateAcrastruct([]byte("test-data"), keypair.Public, nil)
	if err != nil {
		t.Fatal("can't create acrastruct - ", err)
	}

	randomData := make([]byte, 32)
	_, err = rand.Read(randomData)
	if err != nil {
		t.Fatal(err)
	}

	keystore := &mocks.ServerKeyStore{}
	keystore.On("GetClientIDSymmetricKeys", clientID).Return(func([]byte) [][]byte {
		return append([][]byte{}, []byte(`key`))
	}, nil)

	t.Run("OnColumn", func(t *testing.T) {
		t.Run("Check hasMatchEnvelope", func(t *testing.T) {
			envelopeDetector := NewEnvelopeDetector()
			containerDetector := NewOldContainerDetectorWrapper(envelopeDetector)

			rawData := append(randomData, rawAcraBlock...)
			serializedData, err := SerializeEncryptedData(rawData, AcraBlockEnvelopeID)
			if err != nil {
				t.Fatal("can't serialize data - ", err)
			}

			_, outBuffer, err := containerDetector.OnColumn(context.Background(), serializedData)
			if err != nil {
				t.Fatal("OnColumn error ", err)
			}

			if !bytes.Equal(outBuffer, serializedData) {
				t.Fatal("invalid outBuffer - should be equal to initial data")
			}

			if !containerDetector.hasMatchedEnvelope {
				t.Fatal("hasMatchedEnvelope should be true")
			}
		})

		t.Run("Process old containers", func(t *testing.T) {
			type testcase struct {
				Data       []byte
				envelopeID byte
			}
			testCases := []testcase{
				// ProcessAcraBlocks
				{
					Data:       rawAcraBlock,
					envelopeID: AcraBlockEnvelopeID,
				},
				// ProcessAcraStructs
				{
					Data:       rawAcraStruct,
					envelopeID: AcraStructEnvelopeID,
				},
			}

			envelopeDetector := NewEnvelopeDetector()
			containerDetector := NewOldContainerDetectorWrapper(envelopeDetector)

			for _, tcase := range testCases {
				_, outBuffer, err := containerDetector.OnColumn(context.Background(), tcase.Data)
				if err != nil {
					t.Fatal("OnColumn error ", err)
				}

				if len(outBuffer) != len(tcase.Data) {
					t.Fatal("Invalid outBuffer length - outBuffer should be the same")
				}
			}
		})

		t.Run("EnvelopeDetector processing", func(t *testing.T) {
			accessContext := base.NewAccessContext(base.WithClientID(clientID))

			envelopeDetector := NewEnvelopeDetector()
			containerDetector := NewOldContainerDetectorWrapper(envelopeDetector)
			envelopeDetector.AddCallback(NewDecryptHandler(keystore, NewRegistryHandler(keystore)))

			validSerializedData, err := SerializeEncryptedData(rawAcraBlock, AcraBlockEnvelopeID)
			if err != nil {
				t.Fatal("can't serialize data - ", err)
			}

			serializedHeader := []byte{TagSymbol, TagSymbol, TagSymbol}

			newValidSerializedData := func(serialized []byte) []byte {
				if serialized != nil {
					doubleSerialized, err := SerializeEncryptedData(serialized, AcraBlockEnvelopeID)
					if err != nil {
						t.Fatal(err)
					}
					return doubleSerialized
				}

				buf := make([]byte, len(validSerializedData))
				copy(buf, validSerializedData)
				return buf
			}

			type testcase struct {
				input    []byte
				expected []byte
			}
			testCases := []testcase{
				// InvalidSerialized + ValidSerialized
				{
					input:    append(serializeInvalidContainer(rawAcraBlock), validSerializedData...),
					expected: append(serializeInvalidContainer(rawAcraBlock), rawData...),
				},
				// ValidSerialized + ValidSerialized
				{
					input:    append(newValidSerializedData(nil), validSerializedData...),
					expected: append(rawData, rawData...),
				},
				//ValidSerialized + AcraBlock
				{
					input:    append(newValidSerializedData(nil), rawAcraBlock...),
					expected: append(rawData, rawAcraBlock...),
				},
				//SerializedHeader + AcraBlock
				{
					input:    append(serializedHeader, validSerializedData...),
					expected: append(serializedHeader, rawData...),
				},

				// Serialized(Serialized)
				{
					input:    append(newValidSerializedData(validSerializedData)),
					expected: append(newValidSerializedData(validSerializedData)[:SerializedContainerMinSize], rawData...),
				},
			}
			for _, tcase := range testCases {
				ctx, outBuffer, err := containerDetector.OnColumn(base.SetAccessContextToContext(context.Background(), accessContext), tcase.input)
				if err != nil {
					t.Fatal("OnColumn error ", err)
				}
				if !base.IsDecryptedFromContext(ctx) {
					t.Fatal("Expects decrypted data")
				}

				if !bytes.Equal(outBuffer, tcase.expected) {
					t.Fatal("outBuffer is not equals to expected", err)
				}
			}
		})
	})
}

// serializeInvalidContainer accept encrypted data and produce serialized container with invalid envelopeID and length field
func serializeInvalidContainer(encrypted []byte) []byte {
	sumLengthBuf := [SerializedContainerLengthSize]byte{}
	binary.LittleEndian.PutUint64(sumLengthBuf[:], uint64(len(encrypted)))

	serialized := make([]byte, 0, len(encrypted))
	serialized = append(serialized, TagBegin...)
	serialized = append(serialized, sumLengthBuf[:SerializedContainerLengthSize]...)
	serialized = append(serialized, 0xFF) // using unknown value as envelopeID
	serialized = append(serialized, encrypted...)

	return serialized
}
