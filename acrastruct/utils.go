/*
Copyright 2016, Cossack Labs Limited

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

package acrastruct

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
)

// ErrInvalidAcraStruct defines invalid AcraStruct error
var ErrInvalidAcraStruct = errors.New("invalid AcraStruct")

// GetDataLengthFromAcraStruct unpack data length value from AcraStruct
func GetDataLengthFromAcraStruct(data []byte) int {
	dataLengthBlock := data[GetMinAcraStructLength()-DataLengthSize : GetMinAcraStructLength()]
	return int(binary.LittleEndian.Uint64(dataLengthBlock))
}

// GetMinAcraStructLength returns minimal length of AcraStruct
// because in golang we can't declare byte array as constant we need to calculate length of TagBegin in runtime
// or hardcode as constant and maintain len(TagBegin) == CONST_VALUE
func GetMinAcraStructLength() int {
	return len(TagBegin) + KeyBlockLength + DataLengthSize
}

// Errors show incorrect AcraStruct length
var (
	ErrIncorrectAcraStructTagBegin   = errors.New("AcraStruct has incorrect TagBegin")
	ErrIncorrectAcraStructLength     = errors.New("AcraStruct has incorrect length")
	ErrIncorrectAcraStructDataLength = errors.New("AcraStruct has incorrect data length value")
)

// ValidateAcraStructLength check that data has minimal length for AcraStruct and data block equal to data length in AcraStruct
func ValidateAcraStructLength(data []byte) error {
	baseLength := GetMinAcraStructLength()
	if len(data) < baseLength {
		return ErrIncorrectAcraStructLength
	}
	if !bytes.Equal(data[:len(TagBegin)], TagBegin) {
		return ErrIncorrectAcraStructTagBegin
	}
	dataLength := GetDataLengthFromAcraStruct(data)
	if dataLength != len(data[GetMinAcraStructLength():]) {
		return ErrIncorrectAcraStructDataLength
	}
	return nil
}

// ExtractAcraStruct return AcraStruct that stored at start of data and return size in bytes of parsed AcraStructLength
func ExtractAcraStruct(data []byte) (int, []byte, error) {
	if len(data) < GetMinAcraStructLength() {
		return 0, nil, ErrInvalidAcraStruct
	}

	acraStructLength := GetDataLengthFromAcraStruct(data) + GetMinAcraStructLength()
	if acraStructLength < 0 || acraStructLength > len(data) {
		return 0, nil, ErrIncorrectAcraStructLength
	}

	if err := ValidateAcraStructLength(data[:acraStructLength]); err != nil {
		return 0, nil, ErrInvalidAcraStruct
	}

	return acraStructLength, data[:acraStructLength], nil
}

// Processor interface used as callback for recognized AcraStructs and should return data instead AcraStruct
type Processor interface {
	OnAcraStruct(ctx context.Context, acrastruct []byte) ([]byte, error)
}

// ProcessAcraStructs find AcraStructs in inBuffer, call processor on every recognized AcraStruct and replace it with result into outBuffer
// until end of data from inBuffer or any error result
// On error it returns inBuffer as is
func ProcessAcraStructs(ctx context.Context, inBuffer []byte, outBuffer []byte, processor Processor) ([]byte, error) {
	// inline mode
	if len(inBuffer) < GetMinAcraStructLength() {
		copy(outBuffer, inBuffer)
		return outBuffer, nil
	}
	inIndex := 0
	outIndex := 0
	for {
		// search AcraStruct's begin tags through all block of data and try to decrypt
		beginTagIndex := bytes.Index(inBuffer[inIndex:], TagBegin)
		if beginTagIndex == utils.NotFound {
			break
		}
		// convert to absolute index
		beginTagIndex += inIndex
		// write data before start of AcraStruct
		outBuffer = append(outBuffer[:outIndex], inBuffer[inIndex:beginTagIndex]...)
		outIndex += beginTagIndex - inIndex
		inIndex = beginTagIndex
		if len(inBuffer[inIndex:]) > GetMinAcraStructLength() {
			acrastructLength := GetDataLengthFromAcraStruct(inBuffer[inIndex:]) + GetMinAcraStructLength()
			if acrastructLength > 0 && acrastructLength <= len(inBuffer[inIndex:]) {
				endIndex := inIndex + acrastructLength
				processedData, err := processor.OnAcraStruct(ctx, inBuffer[inIndex:endIndex])
				if err != nil {
					return inBuffer, err
				}
				outBuffer = append(outBuffer[:outIndex], processedData...)
				outIndex += len(processedData)
				inIndex += acrastructLength
				continue
			}
		}
		// write current read byte to not process him in next iteration
		// write current read byte to not process him in next iteration
		outBuffer = append(outBuffer[:outIndex], inBuffer[inIndex])
		inIndex++
		outIndex++
		continue
	}
	// copy left bytes
	outBuffer = append(outBuffer[:outIndex], inBuffer[inIndex:]...)
	return outBuffer, nil
}

// ErrNoPrivateKeys is returned when DecryptRotatedAcrastruct is given an empty key list
var ErrNoPrivateKeys = errors.New("cannot decrypt AcraStruct with empty key list")

// DecryptAcrastruct returns plaintext data from AcraStruct, decrypting it using Themis SecureCell in Seal mode,
// using zone as context and privateKey as decryption key.
// Returns error if decryption failed.
func DecryptAcrastruct(data []byte, privateKey *keys.PrivateKey, zone []byte) ([]byte, error) {
	if err := ValidateAcraStructLength(data); err != nil {
		return nil, err
	}
	innerData := data[len(TagBegin):]
	pubkey := &keys.PublicKey{Value: innerData[:PublicKeyLength]}
	smessage := message.New(privateKey, pubkey)
	symmetricKey, err := smessage.Unwrap(innerData[PublicKeyLength:KeyBlockLength])
	if err != nil {
		return []byte{}, err
	}
	//
	var length uint64
	// convert from little endian
	err = binary.Read(bytes.NewReader(innerData[KeyBlockLength:KeyBlockLength+DataLengthSize]), binary.LittleEndian, &length)
	if err != nil {
		return []byte{}, err
	}
	scell, err := cell.SealWithKey(&keys.SymmetricKey{Value: symmetricKey})
	if err != nil {
		return nil, err
	}
	decrypted, err := scell.Decrypt(innerData[KeyBlockLength+DataLengthSize:], zone)
	// fill zero symmetric_key
	utils.ZeroizeSymmetricKey(symmetricKey)
	if err != nil {
		return []byte{}, err
	}
	return decrypted, nil
}

// DecryptRotatedAcrastruct tries decrypting an AcraStruct with a set of rotated keys.
// It either returns decrypted data if one of the keys succeeds, or an error if none is good.
func DecryptRotatedAcrastruct(data []byte, privateKeys []*keys.PrivateKey, zone []byte) ([]byte, error) {
	var err = ErrNoPrivateKeys
	var decryptedData []byte
	for _, privateKey := range privateKeys {
		decryptedData, err = DecryptAcrastruct(data, privateKey, zone)
		if err == nil {
			return decryptedData, nil
		}
	}
	return nil, err
}

// CreateAcrastruct encrypt your data using acra_public key and context (optional)
// and pack into correct Acrastruct format
func CreateAcrastruct(data []byte, acraPublic *keys.PublicKey, context []byte) ([]byte, error) {
	randomKeyPair, err := keys.New(keys.TypeEC)
	if err != nil {
		return nil, err
	}
	// generate random symmetric key
	randomKey := make([]byte, SymmetricKeySize)
	n, err := rand.Read(randomKey)
	if err != nil {
		return nil, err
	}
	if n != SymmetricKeySize {
		return nil, errors.New("read incorrect num of random bytes")
	}

	// create smessage for encrypting symmetric key
	smessage := message.New(randomKeyPair.Private, acraPublic)
	encryptedKey, err := smessage.Wrap(randomKey)
	if err != nil {
		return nil, err
	}
	utils.ZeroizePrivateKey(randomKeyPair.Private)

	// create scell for encrypting data
	scell, err := cell.SealWithKey(&keys.SymmetricKey{Value: randomKey})
	if err != nil {
		return nil, err
	}
	encryptedData, err := scell.Encrypt(data, context)
	if err != nil {
		return nil, err
	}
	utils.ZeroizeSymmetricKey(randomKey)

	// pack acrastruct
	dateLength := make([]byte, DataLengthSize)
	binary.LittleEndian.PutUint64(dateLength, uint64(len(encryptedData)))
	output := make([]byte, len(TagBegin)+KeyBlockLength+DataLengthSize+len(encryptedData))
	output = append(output[:0], TagBegin...)
	output = append(output, randomKeyPair.Public.Value...)
	output = append(output, encryptedKey...)
	output = append(output, dateLength...)
	output = append(output, encryptedData...)
	return output, nil
}
