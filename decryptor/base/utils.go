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

package base

import (
	"bytes"
	"encoding/binary"

	"errors"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
)

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
	scell := cell.New(symmetricKey, cell.CELL_MODE_SEAL)
	decrypted, err := scell.Unprotect(innerData[KeyBlockLength+DataLengthSize:], nil, zone)
	// fill zero symmetric_key
	utils.FillSlice(byte(0), symmetricKey)
	if err != nil {
		return []byte{}, err
	}
	return decrypted, nil
}

// DecryptRotatedAcrastruct tries decrypting an AcraStruct with a set of rotated keys.
// It either returns decrypted data if one of the keys succeeds, or an error if none is good.
func DecryptRotatedAcrastruct(data []byte, privateKeys []*keys.PrivateKey, zone []byte) ([]byte, error) {
	var err error
	var decryptedData []byte
	for _, privateKey := range privateKeys {
		decryptedData, err = DecryptAcrastruct(data, privateKey, zone)
		if err == nil {
			return decryptedData, nil
		}
	}
	return nil, err
}

// CheckPoisonRecord checks if AcraStruct could be decrypted using Poison Record private key.
// Returns true if AcraStruct is poison record, returns false otherwise.
// Returns error if Poison record key is not found.
func CheckPoisonRecord(data []byte, keystorage keystore.KeyStore) (bool, error) {
	poisonKeypair, err := keystorage.GetPoisonKeyPair()
	if err != nil {
		// we can't check on poisoning
		return true, err
	}
	_, err = DecryptAcrastruct(data, poisonKeypair.Private, nil)
	utils.FillSlice(byte(0), poisonKeypair.Private.Value)
	if err == nil {
		// decryption success so it was encrypted with private key for poison records
		return true, nil
	}
	return false, nil
}
