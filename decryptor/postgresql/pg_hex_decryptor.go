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

package postgresql

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"io"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
)

// ZoneID begin tags, lengths, etc
var (
	// TagBegin in hex format
	//var HexTagBegin = []byte{56, 53, 50, 48, 102, 98}
	HexTagBegin          = []byte(hex.EncodeToString(base.TagBegin))
	HexZoneIDBegin       = []byte(hex.EncodeToString(zone.ZoneIDBegin))
	HexZoneTagLength     = len(HexZoneIDBegin)
	HexZoneIDLength      = hex.EncodedLen(16)
	HexZoneIDBlockLength = int(HexZoneTagLength + HexZoneIDLength)
)

// hexEncodedLen return length of hex encoded data of <val> length
func hexEncodedLen(val uint64) uint64 {
	return val * 2
}

// PgHexDecryptor decrypts AcraStruct from Hex-encoded PostgreSQL binary format
type PgHexDecryptor struct {
	currentIndex uint8
	isWithZone   bool
	// buffer for public_key+SM block
	// 2 hex symbols per byte
	keyBlockBuffer [base.KeyBlockLength * 2]byte
	// buffer for decoded from hex public_key+SM block
	//decoded_key_block_buffer [decryptor.KeyBlockLength]byte
	decodedKeyBlockBuffer []byte
	//uint64
	lengthBuf [base.DataLengthSize]byte
	//uint64 in hex
	hexLengthBuf [base.DataLengthSize * 2]byte
	keyStore     keystore.DecryptionKeyStore
	zoneMatcher  *zone.Matcher

	hexBuf []byte
	buf    []byte
	output []byte

	poisonKey []byte
	logger    *log.Entry
}

// NewPgHexDecryptor returns new PgHexDecryptor without zone
func NewPgHexDecryptor() *PgHexDecryptor {
	return &PgHexDecryptor{
		currentIndex:          0,
		isWithZone:            false,
		decodedKeyBlockBuffer: make([]byte, base.KeyBlockLength),
		logger:                log.NewEntry(log.StandardLogger()),
	}
}

// SetLogger set logger
func (decryptor *PgHexDecryptor) SetLogger(logger *log.Entry) {
	decryptor.logger = logger
}

/* check that buf has free space to append length bytes otherwise extend */
func (decryptor *PgHexDecryptor) checkBuf(buf *[]byte, length uint64) {
	if buf == nil || uint64(len(*buf)) < length {
		*buf = make([]byte, length)
	}
}

// MatchBeginTag returns true and updates currentIndex,
// if currentIndex matches beginning of HexTagBegin
func (decryptor *PgHexDecryptor) MatchBeginTag(char byte) bool {
	if char == HexTagBegin[decryptor.currentIndex] {
		decryptor.currentIndex++
		return true
	}
	return false
}

// IsMatched returns true if decryptor has processed HexTagBegin
func (decryptor *PgHexDecryptor) IsMatched() bool {
	return int(decryptor.currentIndex) == len(HexTagBegin)
}

// Reset resets current index
func (decryptor *PgHexDecryptor) Reset() {
	decryptor.currentIndex = 0
}

// GetMatched returns already matched bytes from HexTagBegin
func (decryptor *PgHexDecryptor) GetMatched() []byte {
	return HexTagBegin[:decryptor.currentIndex]
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
	if n != hex.EncodedLen(base.KeyBlockLength) {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Warningln("Can't decode hex data")
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	_, err = hex.Decode(decryptor.decodedKeyBlockBuffer[:], decryptor.keyBlockBuffer[:])
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Warningln("Can't decode hex data")
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	pubkey := &keys.PublicKey{Value: decryptor.decodedKeyBlockBuffer[:base.PublicKeyLength]}

	smessage := message.New(privateKey, pubkey)
	symmetricKey, err := smessage.Unwrap(decryptor.decodedKeyBlockBuffer[base.PublicKeyLength:])
	if err != nil {
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	return symmetricKey, decryptor.keyBlockBuffer[:n], nil
}

func (decryptor *PgHexDecryptor) readDataLength(reader io.Reader) (uint64, []byte, error) {
	var length uint64
	lenCount, err := io.ReadFull(reader, decryptor.hexLengthBuf[:])
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Warningln("Can't read data length")
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
		}
		return 0, decryptor.hexLengthBuf[:lenCount], err
	}
	if lenCount != len(decryptor.hexLengthBuf) {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).Warningf("Incorrect length count, %v!=%v", lenCount, len(decryptor.lengthBuf))
		return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
	}

	// decode hex length to binary length
	n, err := hex.Decode(decryptor.lengthBuf[:], decryptor.hexLengthBuf[:])
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Warningln("Can't decode hex data")
		return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
	}
	if n != len(decryptor.lengthBuf) {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Warningln("Can't decode hex data")
		return 0, decryptor.hexLengthBuf[:lenCount], base.ErrFakeAcraStruct
	}
	// convert from little endian
	binary.Read(bytes.NewReader(decryptor.lengthBuf[:]), binary.LittleEndian, &length)
	return length, decryptor.hexLengthBuf[:], nil
}

func (decryptor *PgHexDecryptor) readScellData(length uint64, reader io.Reader) ([]byte, []byte, error) {
	hexLength := hexEncodedLen(length)
	decryptor.checkBuf(&decryptor.hexBuf, hexLength)
	decryptor.checkBuf(&decryptor.buf, length)
	n, err := io.ReadFull(reader, decryptor.hexBuf[:hexLength])
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Warningf("Can't read scell data with passed length=%v", length)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.hexBuf[:n], err
	}
	if uint64(n) != hexEncodedLen(length) {
		return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
	}
	n, err = hex.Decode(decryptor.buf[:int(length)], decryptor.hexBuf[:hexLength])
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Warningln("Can't decode hex data")
		return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
	}
	if n != int(length) {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).Warningln("Can't decode hex data")
		return nil, decryptor.hexBuf[:n], base.ErrFakeAcraStruct
	}
	return decryptor.buf[:int(length)], decryptor.hexBuf[:hexLength], nil
}

// ReadData returns plaintext content from reader data, decrypting using SecureCell with ZoneID and symmetricKey
func (decryptor *PgHexDecryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
	length, hexLengthBuf, err := decryptor.readDataLength(reader)
	if err != nil {
		return hexLengthBuf, err
	}
	data, hexData, err := decryptor.readScellData(length, reader)
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

	outputLength := hexEncodedLen(uint64(len(decrypted)))
	decryptor.checkBuf(&decryptor.output, outputLength)
	hex.Encode(decryptor.output[:outputLength], decrypted)
	decrypted = nil
	return decryptor.output[:outputLength], nil
}

// GetTagBeginLength returns length of HexTagBegin
func (decryptor *PgHexDecryptor) GetTagBeginLength() int {
	return len(HexTagBegin)
}
