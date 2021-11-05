/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package acrablock

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/acrastruct"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
)

// SymmetricBackend interface abstract backend for key and data encryption
type SymmetricBackend interface {
	Encrypt(key []byte, data []byte, context []byte) ([]byte, error)
	Decrypt(key []byte, data []byte, context []byte) ([]byte, error)
}

// SymmetricDataEncryptionKeyLength size for each new random symmetric key for new AcraBlock
const SymmetricDataEncryptionKeyLength = 32

// Set of constants with sizes of each part of AcraBlock
const (
	TagBeginSize                = 4
	KeyEncryptionKeyTypeSize    = 1
	KeyEncryptionKeyIDSize      = 2
	DataEncryptionKeyLengthSize = 2
	DataEncryptionTypeSize      = 1
	RestAcraBlockLengthSize     = 8
	AcraBlockMinSize            = TagBeginSize + KeyEncryptionKeyTypeSize + KeyEncryptionKeyIDSize + DataEncryptionKeyLengthSize + DataEncryptionTypeSize + RestAcraBlockLengthSize
)

// ErrInvalidAcraBlock defines invalid AcraBlock error
var ErrInvalidAcraBlock = errors.New("invalid AcraBlock")

// SecureCellSymmetricBackend implement SymmetricBackend with SecureCell backend
type SecureCellSymmetricBackend struct{}

// Encrypt SecureCellSymmetricBackend implementation of SymmetricBackend interface for key and data encryption
func (s SecureCellSymmetricBackend) Encrypt(key []byte, data []byte, context []byte) (out []byte, err error) {
	out, _, err = cell.New(key, cell.ModeSeal).Protect(data, context)
	return
}

// Decrypt SecureCellSymmetricBackend implementation of SymmetricBackend interface for key and data decryption
func (s SecureCellSymmetricBackend) Decrypt(key []byte, data []byte, context []byte) (out []byte, err error) {
	out, err = cell.New(key, cell.ModeSeal).Unprotect(data, nil, context)
	return
}

// KeyEncryptionBackendType used as storage for known backends to encrypt symmetric keys in AcraBLock
type KeyEncryptionBackendType uint8

// MarshalBinary encode backend type to bytes
func (k KeyEncryptionBackendType) MarshalBinary() (data []byte, err error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(k))
	return b[:KeyEncryptionKeyTypeSize], nil
}

// Set of known backends for key encryption
const (
	KeyEncryptionBackendTypeSecureCell KeyEncryptionBackendType = iota
)

const defaultKeyEncryptionBackendType = KeyEncryptionBackendTypeSecureCell

// map backend type value to implementation
var keyEncryptionBackendTypeMap = map[KeyEncryptionBackendType]SymmetricBackend{
	KeyEncryptionBackendTypeSecureCell: SecureCellSymmetricBackend{},
}

// DataEncryptionBackendType used as storage for known backends to encrypt data in AcraBlock
type DataEncryptionBackendType uint8

// MarshalBinary encode backend type to bytes
func (t DataEncryptionBackendType) MarshalBinary() (data []byte, err error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(t))
	return b[:DataEncryptionTypeSize], nil
}

// Set of known backends for data encryption in AcraBlock
const (
	DataEncryptionBackendTypeSecureCell DataEncryptionBackendType = iota
)
const defaultDataEncryptionBackendType = DataEncryptionBackendTypeSecureCell

// map backend type value to implementation
var dataEncryptionBackendTypeMap = map[DataEncryptionBackendType]SymmetricBackend{
	DataEncryptionBackendTypeSecureCell: SecureCellSymmetricBackend{},
}

// ErrDataEncryptionKeyGeneration used when can't generate random key with crypto.Rand
var ErrDataEncryptionKeyGeneration = errors.New("can't generate random data encryption key")

// KeyIDGenerator abstract logic to generate ID for symmetric key which will be placed in AcraBlock
type KeyIDGenerator interface {
	GenerateKeyID(key, context []byte) ([]byte, error)
}

// Sha256KeyIDGenerator generate ID for key using sha256 hash function for key value and context
type Sha256KeyIDGenerator struct{}

// GenerateKeyID generate sha256 hash by provided key and context
func (s Sha256KeyIDGenerator) GenerateKeyID(key, context []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(key)
	h.Write(context)
	return h.Sum(nil)[:KeyEncryptionKeyIDSize], nil
}

var defaultKeyIDGenerator KeyIDGenerator = Sha256KeyIDGenerator{}

// AcraBlock array of several parts: TagBegin[4] + LengthOfRestData[4] + KeyEncryptionKeyType[1] + KeyEncryptionKeyID[2] + DataEncryptionType[1] + DataEncryptionKeyLength[2] + EncryptedDataEncryptionKey[*] + EncryptedData[*]
type AcraBlock []byte

var tagBegin = acrastruct.TagBegin[:TagBeginSize]

// NewEmptyAcraBlock create empty block for desired length and filled TagBegin
func NewEmptyAcraBlock(length int) AcraBlock {
	b := make([]byte, length)
	copy(b[:len(tagBegin)], tagBegin)
	return b
}

// SetKeyEncryptionKeyType place marshalled type into AcraBlock
func (b AcraBlock) SetKeyEncryptionKeyType(t KeyEncryptionBackendType) error {
	kekEncryptionType, err := t.MarshalBinary()
	// our MarshalBinary never return any error but we check it here for a future case if we change
	// serialization algorithm that may return error
	if err != nil {
		return err
	}
	copy(b[KeyEncryptionKeyTypePosition:KeyEncryptionKeyTypePosition+KeyEncryptionKeyTypeSize], kekEncryptionType[:KeyEncryptionKeyTypeSize])
	return nil
}

// SetKeyEncryptionKeyID place generated key id into AcraBlock
func (b AcraBlock) SetKeyEncryptionKeyID(key, context []byte, idGenerator KeyIDGenerator) error {
	keyID, err := idGenerator.GenerateKeyID(key, context)
	if err != nil {
		return err
	}
	copy(b[KeyEncryptionKeyIDPosition:KeyEncryptionKeyIDPosition+KeyEncryptionKeyIDSize], keyID[:KeyEncryptionKeyIDSize])
	return nil
}

func (b AcraBlock) getKeyEncryptionKeyID() ([]byte, error) {
	if len(b) < KeyEncryptionKeyIDPosition+KeyEncryptionKeyIDSize {
		return nil, ErrInvalidAcraBlock
	}
	return b[KeyEncryptionKeyIDPosition : KeyEncryptionKeyIDPosition+KeyEncryptionKeyIDSize], nil
}

// setEncryptedDataEncryptionKey place key length and key into AcraBlock
func (b AcraBlock) setEncryptedDataEncryptionKey(key []byte) error {
	if len(b) < EncryptedDataEncryptionKeyPosition+len(key) {
		return ErrInvalidAcraBlock
	}
	buf := [8]byte{}
	binary.LittleEndian.PutUint32(buf[:], uint32(len(key)))
	copy(b[DataEncryptionKeyLengthPosition:DataEncryptionKeyLengthPosition+DataEncryptionKeyLengthSize], buf[:DataEncryptionKeyLengthSize])
	copy(b[EncryptedDataEncryptionKeyPosition:EncryptedDataEncryptionKeyPosition+len(key)], key)
	return nil
}

// SetDataEncryptionType place marshalled type into AcraBlock
func (b AcraBlock) SetDataEncryptionType(t DataEncryptionBackendType) error {
	dataEncryptionType, err := t.MarshalBinary()
	if err != nil {
		return err
	}
	copy(b[DataEncryptionTypePosition:DataEncryptionTypePosition+DataEncryptionTypeSize], dataEncryptionType[:DataEncryptionTypeSize])
	return nil
}

// setEncryptedData place data into AcraBlock. Note: should be used only after setEncryptedDataEncryptionKey call
// because need to know key size before place data by AcraBlock.EncryptedDataEncryptionKeyLength call
func (b AcraBlock) setEncryptedData(data []byte) error {
	if len(b) < EncryptedDataEncryptionKeyPosition {
		return ErrInvalidAcraBlock
	}
	keySize := b.EncryptedDataEncryptionKeyLength()
	if len(b) < EncryptedDataEncryptionKeyPosition+keySize {
		return ErrInvalidAcraBlock
	}
	if n := copy(b[EncryptedDataEncryptionKeyPosition+keySize:], data); n != len(data) {
		return ErrInvalidAcraBlock
	}
	return nil
}

// Build create final acraBlock by encryptedKey and encryptedData
func (b AcraBlock) Build(encryptedKey, encryptedData []byte) ([]byte, error) {
	if err := b.setEncryptedDataEncryptionKey(encryptedKey); err != nil {
		return nil, err
	}
	if err := b.setEncryptedData(encryptedData); err != nil {
		return nil, err
	}
	sumLength := len(b) - TagBeginSize
	sumLengthBuf := [8]byte{}
	binary.LittleEndian.PutUint64(sumLengthBuf[:], uint64(sumLength))
	copy(b[TagBeginSize:TagBeginSize+RestAcraBlockLengthSize], sumLengthBuf[:RestAcraBlockLengthSize])
	return b, nil
}

// AcraBlock length parts constants
const (
	RestAcraBlockLengthPosition        = TagBeginSize
	KeyEncryptionKeyTypePosition       = RestAcraBlockLengthPosition + RestAcraBlockLengthSize
	KeyEncryptionKeyIDPosition         = KeyEncryptionKeyTypePosition + KeyEncryptionKeyTypeSize
	DataEncryptionTypePosition         = KeyEncryptionKeyIDPosition + KeyEncryptionKeyIDSize
	DataEncryptionKeyLengthPosition    = DataEncryptionTypePosition + DataEncryptionTypeSize
	EncryptedDataEncryptionKeyPosition = DataEncryptionKeyLengthPosition + DataEncryptionKeyLengthSize
)

// KeyEncryptionBackend read SymmetricBackend by KeyEncryptionKeyTypePosition
func (b AcraBlock) KeyEncryptionBackend() SymmetricBackend {
	return keyEncryptionBackendTypeMap[KeyEncryptionBackendType(b[KeyEncryptionKeyTypePosition])]
}

// DataEncryptionBackend read SymmetricBackend by DataEncryptionTypePosition
func (b AcraBlock) DataEncryptionBackend() SymmetricBackend {
	return dataEncryptionBackendTypeMap[DataEncryptionBackendType(b[DataEncryptionTypePosition])]
}

// EncryptedDataEncryptionKeyLength return encryption key length of encrypted data
func (b AcraBlock) EncryptedDataEncryptionKeyLength() int {
	return int(binary.LittleEndian.Uint16(b[DataEncryptionKeyLengthPosition : DataEncryptionKeyLengthPosition+DataEncryptionKeyLengthSize]))
}

// Decrypt AcraBlock using all keys sequentially until successful decryption and context
func (b AcraBlock) Decrypt(keys [][]byte, context []byte) ([]byte, error) {
	keySize := b.EncryptedDataEncryptionKeyLength()
	encryptedKey := b[EncryptedDataEncryptionKeyPosition : EncryptedDataEncryptionKeyPosition+keySize]
	encryptedData := b[AcraBlockMinSize+keySize:]
	keyEncryptionKeyBackend := b.KeyEncryptionBackend()
	dataEncryptionBackend := b.DataEncryptionBackend()
	blockKeyID, err := b.getKeyEncryptionKeyID()
	if err != nil {
		return nil, err
	}
	var dataEncryptionKey []byte
	for _, key := range keys {
		keyID, err := Sha256KeyIDGenerator{}.GenerateKeyID(key, context)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(keyID, blockKeyID) {
			decryptedKey, err := keyEncryptionKeyBackend.Decrypt(key, encryptedKey, context)
			if err == nil {
				dataEncryptionKey = decryptedKey
				break
			}
		}
	}
	if dataEncryptionKey == nil {
		return nil, ErrInvalidAcraBlock
	}
	decryptedData, err := dataEncryptionBackend.Decrypt(dataEncryptionKey, encryptedData, context)
	utils.ZeroizeSymmetricKey(dataEncryptionKey)
	if err != nil {
		return nil, ErrInvalidAcraBlock
	}
	return decryptedData, nil
}

const (
	// AcraBlock valid if correct TagBegin (1) + correct length of rest part (2) + known key encryption backend (3)
	// + known data encryption backend (4)
	validAcraBlockMask = 1 << 4
)

// ExtractAcraBlockFromData return AcraBlock that stored at start of data and return size in bytes of parsed AcraBlockLength
func ExtractAcraBlockFromData(data []byte) (int, AcraBlock, error) {
	if len(data) < AcraBlockMinSize {
		return 0, nil, ErrInvalidAcraBlock
	}
	validMask := 1
	if bytes.Equal(data[:TagBeginSize], acrastruct.TagBegin[:TagBeginSize]) {
		validMask <<= 1
	}
	restLength := binary.LittleEndian.Uint64(data[RestAcraBlockLengthPosition : RestAcraBlockLengthPosition+RestAcraBlockLengthSize])
	if len(data) >= int(restLength+TagBeginSize) {
		validMask <<= 1
	}
	_, ok := keyEncryptionBackendTypeMap[KeyEncryptionBackendType(data[KeyEncryptionKeyTypePosition])]
	if ok {
		validMask <<= 1
	}
	_, ok = dataEncryptionBackendTypeMap[DataEncryptionBackendType(data[DataEncryptionTypePosition])]
	if ok {
		validMask <<= 1
	}
	if validMask != validAcraBlockMask {
		return 0, nil, ErrInvalidAcraBlock
	}
	length := TagBeginSize + restLength
	return int(length), AcraBlock(data[:length]), nil

}

// NewAcraBlockFromData expects that whole data is one AcraBlock, validate and return, otherwise error
func NewAcraBlockFromData(data []byte) (AcraBlock, error) {
	_, block, err := ExtractAcraBlockFromData(data)
	if err != nil {
		return nil, err
	}
	return block, nil
}

// CreateAcraBlock construct AcraBlock like
// tag_begin[4] + rest_sum_length[*] + kek_encryption_type[1] + kek_id[2] + data_encryption_type[1] + dek_length[2] + dek + encrypted_data
func CreateAcraBlock(data []byte, key []byte, context []byte) ([]byte, error) {
	return CreateAcraBlockWithBackends(data, key, context, defaultKeyEncryptionBackendType, defaultDataEncryptionBackendType)
}

// CreateAcraBlockWithBackends create AcraBlock using specified encryption backends
func CreateAcraBlockWithBackends(data []byte, key []byte, context []byte, keyEncryptionBackend KeyEncryptionBackendType, dataEncryptionBackend DataEncryptionBackendType) ([]byte, error) {
	dataEncryptionKey := make([]byte, 32)
	n, err := rand.Read(dataEncryptionKey)
	if err != nil {
		return nil, err
	}
	if n != SymmetricDataEncryptionKeyLength {
		return nil, ErrDataEncryptionKeyGeneration
	}
	dataEncryptor := dataEncryptionBackendTypeMap[dataEncryptionBackend]
	encryptedData, err := dataEncryptor.Encrypt(dataEncryptionKey, data, context)
	if err != nil {
		return nil, err
	}
	keyEncryptionKeyEncryptor := keyEncryptionBackendTypeMap[keyEncryptionBackend]
	encryptedDataEncryptionKey, err := keyEncryptionKeyEncryptor.Encrypt(key, dataEncryptionKey, context)
	if err != nil {
		return nil, err
	}
	utils.ZeroizeSymmetricKey(dataEncryptionKey)

	acraBlock := NewEmptyAcraBlock(AcraBlockMinSize + len(encryptedData) + len(encryptedDataEncryptionKey))
	if err := acraBlock.SetKeyEncryptionKeyType(keyEncryptionBackend); err != nil {
		return nil, err
	}
	if err := acraBlock.SetKeyEncryptionKeyID(key, context, defaultKeyIDGenerator); err != nil {
		return nil, err
	}
	if err := acraBlock.SetDataEncryptionType(dataEncryptionBackend); err != nil {
		return nil, err
	}
	return acraBlock.Build(encryptedDataEncryptionKey, encryptedData)
}
