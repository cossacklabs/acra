// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package binary

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	"io"
	"log"
)

type BinaryDecryptor struct {
	currentIndex    uint8
	isWithZone      bool
	isWholeMatch    bool
	keyBlockBuffer  []byte
	lengthBuf       [base.DATA_LENGTH_SIZE]byte
	buf             []byte
	keyStore        keystore.KeyStore
	zoneMatcher     *zone.ZoneIdMatcher
	poisonKey       []byte
	clientId        []byte
	callbackStorage *base.PoisonCallbackStorage
}

func NewBinaryDecryptor(clientId []byte) *BinaryDecryptor {
	return &BinaryDecryptor{keyBlockBuffer: make([]byte, base.KEY_BLOCK_LENGTH), clientId: clientId}
}

/* not implemented Decryptor interface */
func (decryptor *BinaryDecryptor) MatchBeginTag(char byte) bool {
	if char == base.TAG_BEGIN[decryptor.currentIndex] {
		decryptor.currentIndex++
		return true
	}
	return false
}
func (decryptor *BinaryDecryptor) IsMatched() bool {
	return len(base.TAG_BEGIN) == int(decryptor.currentIndex)
}
func (decryptor *BinaryDecryptor) Reset() {
	decryptor.currentIndex = 0
}
func (decryptor *BinaryDecryptor) GetMatched() []byte {
	return base.TAG_BEGIN[:decryptor.currentIndex]
}
func (decryptor *BinaryDecryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	n, err := io.ReadFull(reader, decryptor.keyBlockBuffer[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.keyBlockBuffer[:n], err
	}
	pubkey := &keys.PublicKey{Value: decryptor.keyBlockBuffer[:base.PUBLIC_KEY_LENGTH]}

	smessage := message.New(privateKey, pubkey)
	symmetricKey, err := smessage.Unwrap(decryptor.keyBlockBuffer[base.PUBLIC_KEY_LENGTH:])
	if err != nil {
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	return symmetricKey, decryptor.keyBlockBuffer[:n], nil
}

func (decryptor *BinaryDecryptor) readDataLength(reader io.Reader) (uint64, []byte, error) {
	var length uint64
	lenCount, err := io.ReadFull(reader, decryptor.lengthBuf[:])
	if err != nil {
		log.Printf("Warning: %v\n", utils.ErrorMessage("can't read data length", err))
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return uint64(lenCount), decryptor.lengthBuf[:lenCount], base.ErrFakeAcraStruct
		}
		return 0, []byte{}, err
	}
	if lenCount != len(decryptor.lengthBuf) {
		log.Printf("Warning: incorrect length count, %v!=%v\n", lenCount, len(decryptor.lengthBuf))
		return 0, decryptor.lengthBuf[:lenCount], base.ErrFakeAcraStruct
	}
	// convert from little endian
	binary.Read(bytes.NewReader(decryptor.lengthBuf[:]), binary.LittleEndian, &length)
	return length, decryptor.lengthBuf[:], nil
}

func (decryptor *BinaryDecryptor) checkBuf(buf *[]byte, length int) {
	if buf == nil || len(*buf) < length {
		*buf = make([]byte, length)
	}
}

func (decryptor *BinaryDecryptor) readScellData(length int, reader io.Reader) ([]byte, []byte, error) {
	decryptor.checkBuf(&decryptor.buf, int(length))
	n, err := io.ReadFull(reader, decryptor.buf[:length])
	if err != nil {
		log.Printf("Warning: %v\n", utils.ErrorMessage(fmt.Sprintf("can't read scell data with passed length=%v", length), err))
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.buf[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.buf[:n], err
	}
	if n != int(length) {
		log.Printf("Warning: %v\n", utils.ErrorMessage("can't decode hex data", err))
		return nil, decryptor.buf[:n], base.ErrFakeAcraStruct
	}
	return decryptor.buf[:length], decryptor.buf[:length], nil
}

func (decryptor *BinaryDecryptor) ReadData(symmetricKey, zoneId []byte, reader io.Reader) ([]byte, error) {
	length, rawLengthData, err := decryptor.readDataLength(reader)
	if err != nil {
		return rawLengthData, err
	}
	data, rawData, err := decryptor.readScellData(int(length), reader)
	if err != nil {
		return append(rawLengthData, rawData...), err
	}

	scell := cell.New(symmetricKey, cell.CELL_MODE_SEAL)
	decrypted, err := scell.Unprotect(data, nil, zoneId)
	data = nil
	// fill zero symmetric_key
	utils.FillSlice(byte(0), symmetricKey)
	if err != nil {
		return append(rawLengthData, rawData...), base.ErrFakeAcraStruct
	}
	return decrypted, nil
}

func (*BinaryDecryptor) GetTagBeginLength() int {
	return len(base.TAG_BEGIN)
}
