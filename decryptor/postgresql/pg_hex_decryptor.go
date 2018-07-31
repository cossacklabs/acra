// Package postgresql contains postgresql decryptor.
//
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
package postgresql

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"io"

	"fmt"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
)

// ZoneID begin tags, lengths, etc
var (
	// TAG_BEGIN in hex format
	//var HEX_TAG_BEGIN = []byte{56, 53, 50, 48, 102, 98}
	HEX_TAG_BEGIN            = []byte(hex.EncodeToString(base.TAG_BEGIN))
	HEX_ZONE_ID_BEGIN        = []byte(hex.EncodeToString(zone.ZONE_ID_BEGIN))
	HEX_ZONE_TAG_LENGTH      = len(HEX_ZONE_ID_BEGIN)
	HEX_ZONE_ID_LENGTH       = hex.EncodedLen(16)
	HEX_ZONE_ID_BLOCK_LENGTH = int(HEX_ZONE_TAG_LENGTH + HEX_ZONE_ID_LENGTH)
)

// PgHexDecryptor decrypts AcraStruct from Hex-encoded PostgreSQL binary format
type PgHexDecryptor struct {
	currentIndex uint8
	isWithZone   bool
	// buffer for public_key+SM block
	// 2 hex symbols per byte
	keyBlockBuffer [base.KEY_BLOCK_LENGTH * 2]byte
	// buffer for decoded from hex public_key+SM block
	//decoded_key_block_buffer [decryptor.KEY_BLOCK_LENGTH]byte
	decodedKeyBlockBuffer []byte
	//uint64
	lengthBuf [base.DATA_LENGTH_SIZE]byte
	//uint64 in hex
	hexLengthBuf [base.DATA_LENGTH_SIZE * 2]byte
	keyStore     keystore.KeyStore
	zoneMatcher  *zone.ZoneIDMatcher

	hexBuf []byte
	buf    []byte
	output []byte

	poisonKey       []byte
	callbackStorage *base.PoisonCallbackStorage
}

// NewPgHexDecryptor returns new PgHexDecryptor without zone
func NewPgHexDecryptor() *PgHexDecryptor {
	return &PgHexDecryptor{
		currentIndex:          0,
		isWithZone:            false,
		decodedKeyBlockBuffer: make([]byte, base.KEY_BLOCK_LENGTH),
	}
}

/* check that buf has free space to append length bytes otherwise extend */
func (decryptor *PgHexDecryptor) checkBuf(buf *[]byte, length int) {
	if buf == nil || len(*buf) < length {
		*buf = make([]byte, length)
	}
}

// MatchBeginTag returns true and updates currentIndex,
// if currentIndex matches beginning of HEX_TAG_BEGIN
func (decryptor *PgHexDecryptor) MatchBeginTag(char byte) bool {
	if char == HEX_TAG_BEGIN[decryptor.currentIndex] {
		decryptor.currentIndex++
		return true
	}
	return false
}

// IsMatched returns true if decryptor has processed HEX_TAG_BEGIN
func (decryptor *PgHexDecryptor) IsMatched() bool {
	return int(decryptor.currentIndex) == len(HEX_TAG_BEGIN)
}

// Reset resets current index
func (decryptor *PgHexDecryptor) Reset() {
	decryptor.currentIndex = 0
}

// GetMatched returns already matched bytes from HEX_TAG_BEGIN
func (decryptor *PgHexDecryptor) GetMatched() []byte {
	return HEX_TAG_BEGIN[:decryptor.currentIndex]
}

// ReadSymmetricKey decrypts symmetric key hidden in AcraStruct using SecureMessage and privateKey
// returns decrypted symmetric key or ErrFakeAcraStruct error if can't decrypt
func (decryptor *PgHexDecryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	n, err := io.ReadFull(reader, decryptor.keyBlockBuffer[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.keyBlockBuffer[:n], err
	}
	if n != hex.EncodedLen(base.KEY_BLOCK_LENGTH) {
		log.Warningf("%v", utils.ErrorMessage("Can't decode hex data", err))
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	_, err = hex.Decode(decryptor.decodedKeyBlockBuffer[:], decryptor.keyBlockBuffer[:])
	if err != nil {
		log.Warningf("%v", utils.ErrorMessage("Can't decode hex data", err))
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	pubkey := &keys.PublicKey{Value: decryptor.decodedKeyBlockBuffer[:base.PUBLIC_KEY_LENGTH]}

	smessage := message.New(privateKey, pubkey)
	symmetricKey, err := smessage.Unwrap(decryptor.decodedKeyBlockBuffer[base.PUBLIC_KEY_LENGTH:])
	if err != nil {
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	return symmetricKey, decryptor.keyBlockBuffer[:n], nil
}

func (decryptor *PgHexDecryptor) readDataLength(reader io.Reader) (uint64, []byte, error) {
	var length uint64
	lenCount, err := io.ReadFull(reader, decryptor.hexLengthBuf[:])
	if err != nil {
		log.Warningf("%v", utils.ErrorMessage("can't read data length", err))
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
		}
		return 0, decryptor.hexLengthBuf[:lenCount], err
	}
	if lenCount != len(decryptor.hexLengthBuf) {
		log.Warningf("incorrect length count, %v!=%v", lenCount, len(decryptor.lengthBuf))
		return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
	}

	// decode hex length to binary length
	n, err := hex.Decode(decryptor.lengthBuf[:], decryptor.hexLengthBuf[:])
	if err != nil {
		log.Warningf("%v", utils.ErrorMessage("Can't decode hex data", err))
		return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
	}
	if n != len(decryptor.lengthBuf) {
		log.Warningf("%v", utils.ErrorMessage("Can't decode hex data", err))
		return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
	}
	// convert from little endian
	binary.Read(bytes.NewReader(decryptor.lengthBuf[:]), binary.LittleEndian, &length)
	return length, decryptor.hexLengthBuf[:], nil
}
func (decryptor *PgHexDecryptor) readScellData(length int, reader io.Reader) ([]byte, []byte, error) {
	hexLength := hex.EncodedLen(int(length))
	decryptor.checkBuf(&decryptor.hexBuf, hexLength)
	decryptor.checkBuf(&decryptor.buf, int(length))
	n, err := io.ReadFull(reader, decryptor.hexBuf[:hexLength])
	if err != nil {
		log.Warningf("%v", utils.ErrorMessage(fmt.Sprintf("can't read scell data with passed length=%v", length), err))
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.hexBuf[:n], err
	}
	if n != hex.EncodedLen(length) {
		return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
	}
	n, err = hex.Decode(decryptor.buf[:int(length)], decryptor.hexBuf[:hexLength])
	if err != nil {
		log.Warningf("%v", utils.ErrorMessage("Can't decode hex data", err))
		return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
	}
	if n != int(length) {
		log.Warningf("%v", utils.ErrorMessage("Can't decode hex data", err))
		return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
	}
	return decryptor.buf[:int(length)], decryptor.hexBuf[:hexLength], nil
}

func (*PgHexDecryptor) getFullDataLength(dataLength uint64) int {
	// original data is tag_begin+key_block+data_length+data
	// output data length should be hex(original_data)
	return hex.EncodedLen(len(base.TAG_BEGIN) + base.KEY_BLOCK_LENGTH + 8 + int(dataLength))
}

// ReadData returns plaintext content from reader data, decrypting using SecureCell with ZoneID and symmetricKey
func (decryptor *PgHexDecryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
	length, hexLengthBuf, err := decryptor.readDataLength(reader)
	if err != nil {
		return hexLengthBuf, err
	}
	data, hexData, err := decryptor.readScellData(int(length), reader)
	if err != nil {
		return append(hexLengthBuf, hexData...), err
	}

	scell := cell.New(symmetricKey, cell.CELL_MODE_SEAL)

	decrypted, err := scell.Unprotect(data, nil, zoneID)
	data = nil
	// fill zero symmetric_key
	utils.FillSlice(byte(0), symmetricKey)
	if err != nil {
		return append(hexLengthBuf, hexData...), base.ErrFakeAcraStruct
	}

	outputLength := hex.EncodedLen(len(decrypted))
	decryptor.checkBuf(&decryptor.output, outputLength)
	hex.Encode(decryptor.output[:outputLength], decrypted)
	decrypted = nil
	return decryptor.output[:outputLength], nil
}

// GetTagBeginLength returns length of HEX_TAG_BEGIN
func (decryptor *PgHexDecryptor) GetTagBeginLength() int {
	return len(HEX_TAG_BEGIN)
}
