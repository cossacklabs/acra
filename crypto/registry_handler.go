package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/acrablock"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
)

// Errors related to crypto handlers
var (
	ErrDecryptionError = errors.New("decryption error")
	ErrEmptyKeystore   = errors.New("nil keystore in context")
)

// TagSymbol used in begin of serialized container
const TagSymbol byte = '%'

// Serialized container meta info constants
const (
	TagBeginSize                  = 3
	SerializedContainerLengthSize = 8
	EnvelopeIDLengthSize          = 1
	SerializedContainerMinSize    = TagBeginSize + SerializedContainerLengthSize + EnvelopeIDLengthSize
)

// TagBegin represents begin sequence of bytes for serialized container.
var TagBegin = []byte{TagSymbol, TagSymbol, TagSymbol}

// RegistryHandler related errors
var (
	ErrIncorrectSerializedContainer   = errors.New("incorrect serialized container format")
	ErrEmptyEncryptedData             = errors.New("empty encrypted data")
	ErrInvalidInternalContainer       = errors.New("invalid internal container")
	ErrOldContainerMatched            = errors.New("old container matched")
	ErrNoOldContainerMatched          = errors.New("no old container matched")
	ErrNoSerializedContainerExtracted = errors.New("no serialized container extracted")
)

// ContainerHandler represent container handler interface used as encryptor/decryptor/processor
type ContainerHandler interface {
	Name() string // used to match names from config file
	ID() byte     // used to serialize into binary container or match from data

	//MatchDataSignature ExtendedDataProcessor's method
	MatchDataSignature([]byte) bool

	Decrypt(data []byte, context *base.DataProcessorContext) ([]byte, error)

	//EncryptWithClientID and EncryptWithZoneID DataEncryptor's interface methods
	EncryptWithClientID(clientID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error)
	EncryptWithZoneID(zoneID, data []byte, context *encryptor.DataEncryptorContext) ([]byte, error)
}

// RegistryHandler implements CryptoContainerHandler that implements DataEncryptor/DataProcessor interfaces and may be used
// by OnBind/OnQuery/OnColumn subscribers (masking, transparent decryption ) to encrypt/decrypt data and uses private registry
type RegistryHandler struct {
	keystore keystore.DataEncryptorKeyStore
}

// NewRegistryHandler construct new RegistryHandler struct with encryptor.EmptyCheckFunction as SkipEncryptionFunc
func NewRegistryHandler(keystorage keystore.DataEncryptorKeyStore) RegistryHandler {
	return RegistryHandler{
		keystore: keystorage,
	}
}

// MatchDataSignature implementation of ContainerHandler.MatchDataSignature method
func (r RegistryHandler) MatchDataSignature(data []byte) bool {
	internal, envelopeID, err := DeserializeEncryptedData(data)
	if err != nil {
		return false
	}

	handler, err := GetHandlerByEnvelopeID(envelopeID)
	if err != nil {
		return false
	}

	return handler.MatchDataSignature(internal)
}

// Process implementation of ContainerHandler.Process method
func (r RegistryHandler) Process(data []byte, context *base.DataProcessorContext) ([]byte, error) {
	envelopeID, err := getEnvelopeIDFromData(data)
	if err != nil && err != ErrOldContainerMatched {
		return nil, err
	}

	handler, err := GetHandlerByEnvelopeID(envelopeID)
	if err != nil {
		return nil, err
	}
	return r.DecryptWithHandler(handler, data, context)
}

// EncryptWithClientID implementation of ContainerHandler.EncryptWithClientID method
func (r RegistryHandler) EncryptWithClientID(clientID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	handler, err := GetHandlerByName(string(setting.GetCryptoEnvelope()))
	if err != nil {
		return nil, err
	}

	// case when data encrypted on app side (for example AcraStructs with AcraWriter) and should not be encrypted second time
	if handler.MatchDataSignature(data) || r.MatchDataSignature(data) {
		return data, nil
	}

	encrypted, err := handler.EncryptWithClientID(clientID, data, &encryptor.DataEncryptorContext{Keystore: r.keystore})
	if err != nil {
		return nil, err
	}

	return SerializeEncryptedData(encrypted, handler.ID())
}

// EncryptWithHandler call EncryptWithClientID/EncryptWithZoneID with specified handler
func (r RegistryHandler) EncryptWithHandler(handler ContainerHandler, id, data []byte, withZone bool) ([]byte, error) {
	// case when data encrypted on app side (for example AcraStructs with AcraWriter) and should not be encrypted second time
	if handler.MatchDataSignature(data) || r.MatchDataSignature(data) {
		return data, nil
	}
	var err error
	var encrypted []byte
	if withZone {
		encrypted, err = handler.EncryptWithZoneID(id, data, &encryptor.DataEncryptorContext{Keystore: r.keystore})
	} else {
		encrypted, err = handler.EncryptWithClientID(id, data, &encryptor.DataEncryptorContext{Keystore: r.keystore})
	}
	if err != nil {
		return nil, err
	}

	return SerializeEncryptedData(encrypted, handler.ID())
}

// DecryptWithHandler decrypts data using specified handler
func (r RegistryHandler) DecryptWithHandler(handler ContainerHandler, data []byte, context *base.DataProcessorContext) ([]byte, error) {
	internal, _, err := DeserializeEncryptedData(data)
	if err != nil {
		return nil, err
	}

	if !handler.MatchDataSignature(internal) {
		return nil, ErrInvalidInternalContainer
	}

	processed, err := handler.Decrypt(internal, context)
	if err != nil {
		if err == ErrEmptyKeystore {
			return data, nil
		}
		return nil, err
	}

	return processed, nil
}

// EncryptWithZoneID implementation of ContainerHandler.EncryptWithZoneID method
func (r RegistryHandler) EncryptWithZoneID(zoneID, data []byte, setting config.ColumnEncryptionSetting) ([]byte, error) {
	handler, err := GetHandlerByName(string(setting.GetCryptoEnvelope()))
	if err != nil {
		return nil, err
	}

	// case when data encrypted on app side (for example AcraStructs with AcraWriter) and should not be encrypted second time
	if handler.MatchDataSignature(data) || r.MatchDataSignature(data) {
		return data, nil
	}

	encrypted, err := handler.EncryptWithZoneID(zoneID, data, &encryptor.DataEncryptorContext{Keystore: r.keystore})
	if err != nil {
		return nil, err
	}

	return SerializeEncryptedData(encrypted, handler.ID())
}

// SerializeEncryptedData wraps encrypted data in new format container
func SerializeEncryptedData(encrypted []byte, envelopeID byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, ErrEmptyEncryptedData
	}

	// <header> + <length> + <envelope_id> + <envelope_specific_rest_part>
	length := len(TagBegin) + SerializedContainerLengthSize + EnvelopeIDLengthSize + len(encrypted)

	sumLengthBuf := [SerializedContainerLengthSize]byte{}
	binary.LittleEndian.PutUint64(sumLengthBuf[:], uint64(length))

	serialized := make([]byte, 0, length)
	serialized = append(serialized, TagBegin...)
	serialized = append(serialized, sumLengthBuf[:SerializedContainerLengthSize]...)
	serialized = append(serialized, envelopeID)
	serialized = append(serialized, encrypted...)

	return serialized, nil
}

// DeserializeEncryptedData derive internal container
func DeserializeEncryptedData(encrypted []byte) ([]byte, byte, error) {
	envelopeID, err := getEnvelopeIDFromData(encrypted)
	if err != nil {
		if err == ErrOldContainerMatched {
			return encrypted, envelopeID, nil
		}
		return nil, 0, err
	}

	internalLength, err := getSerializedContainerLength(encrypted)
	if err != nil {
		return nil, 0, err
	}
	internal := make([]byte, int(internalLength))

	copy(internal, encrypted[SerializedContainerMinSize:])
	return internal, envelopeID, nil
}

//ExtractSerializedContainer retrieve length of wrapping container
func ExtractSerializedContainer(data []byte) (int, []byte, error) {
	_, err := validateSerializedContainer(data)
	if err == nil {
		length := binary.LittleEndian.Uint64(data[len(TagBegin) : len(TagBegin)+SerializedContainerLengthSize])
		return int(length), data, nil
	}

	//trying to match whole block to internal container AcraStruct or AcraBlock
	if envelopeID, length, err := matchOldContainer(data); err == nil {
		// in case of matched container we serialize it only for next processing
		serialized, err := SerializeEncryptedData(data, envelopeID)
		if err != nil {
			return 0, nil, err
		}
		return length, serialized, nil
	}

	return 0, nil, ErrNoSerializedContainerExtracted
}

// getEnvelopeIDFromData return envelopeID from data
func getEnvelopeIDFromData(data []byte) (byte, error) {
	envelopeID, err := validateSerializedContainer(data)
	if err == nil {
		return envelopeID, nil
	}

	if matchedEnvelopeID, _, err := matchOldContainer(data); err == nil {
		// matched old container
		return matchedEnvelopeID, ErrOldContainerMatched
	}
	return 0, err
}

// validateSerializedContainer validate serialized container
func validateSerializedContainer(data []byte) (byte, error) {
	if len(data) <= SerializedContainerMinSize {
		return 0, ErrIncorrectSerializedContainer
	}

	if !bytes.Equal(data[:len(TagBegin)], TagBegin) {
		return 0, ErrIncorrectSerializedContainer
	}

	envelopeID := data[TagBeginSize+SerializedContainerLengthSize]
	_, err := GetHandlerByEnvelopeID(envelopeID)
	if err != nil {
		return 0, ErrHandlerNotFound
	}

	return envelopeID, nil
}

// for backward compatibility purpose we try to match data to AcraStruct or Acrablock
func matchOldContainer(data []byte) (byte, int, error) {
	if err := acrastruct.ValidateAcraStructLength(data); err == nil {
		return AcraStructEnvelopeID, acrastruct.GetDataLengthFromAcraStruct(data) + acrastruct.GetMinAcraStructLength(), nil
	}

	if length, _, err := acrablock.ExtractAcraBlockFromData(data); err == nil {
		return AcraBlockEnvelopeID, length, nil
	}

	return 0, 0, ErrNoOldContainerMatched
}

// getSerializedContainerLength return length of serialized container
func getSerializedContainerLength(encrypted []byte) (uint64, error) {
	length := binary.LittleEndian.Uint64(encrypted[len(TagBegin) : len(TagBegin)+SerializedContainerLengthSize])
	internalLength := length - uint64(SerializedContainerMinSize)

	if internalLength < 0 || internalLength > uint64(len(encrypted)-SerializedContainerMinSize) {
		return 0, ErrIncorrectSerializedContainer
	}
	return internalLength, nil
}
