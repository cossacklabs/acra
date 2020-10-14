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
	"io"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	log "github.com/sirupsen/logrus"
)

// ZoneID begin tags, lengths, etc
var (
	EscapeTagBegin          = utils.EncodeToOctal(base.TagBegin)
	EscapeZoneTagLength     = zone.ZoneTagLength
	EscapeZoneIDBlockLength = zone.ZoneIDBlockLength
)

// PgEscapeDecryptor decrypts AcraStruct from Escape-encoded PostgreSQL binary format
type PgEscapeDecryptor struct {
	currentIndex uint8
	outputSize   int
	// max size can be 4 characters for octal representation per byte
	octKeyBlockBuffer     [base.KeyBlockLength * 4]byte
	decodedKeyBlockBuffer []byte
	//uint64
	lengthBuf [8]byte
	// 4 oct symbols (\000) ber byte
	octLengthBuf [8 * 4]byte
	octCharBuf   [3]byte
	logger       *log.Entry
}

// NewPgEscapeDecryptor returns new PgEscapeDecryptor
func NewPgEscapeDecryptor() *PgEscapeDecryptor {
	return &PgEscapeDecryptor{
		currentIndex:          0,
		outputSize:            0,
		decodedKeyBlockBuffer: make([]byte, base.KeyBlockLength),
		logger:                log.NewEntry(log.StandardLogger()),
	}
}

// SetLogger set logger
func (decryptor *PgEscapeDecryptor) SetLogger(logger *log.Entry) {
	decryptor.logger = logger
}

// MatchBeginTag returns true and updates currentIndex and outputSize,
// if currentIndex matches beginning of EscapeTagBegin
func (decryptor *PgEscapeDecryptor) MatchBeginTag(char byte) bool {
	if char == EscapeTagBegin[decryptor.currentIndex] {
		decryptor.currentIndex++
		decryptor.outputSize++
		return true
	}
	return false
}

// IsMatched returns true if decryptor has processed EscapeTagBegin
func (decryptor *PgEscapeDecryptor) IsMatched() bool {
	return int(decryptor.currentIndex) == len(EscapeTagBegin)
}

// Reset resets current index and output size
func (decryptor *PgEscapeDecryptor) Reset() {
	decryptor.currentIndex = 0
	decryptor.outputSize = 0
}

// GetMatched returns already matched bytes from EscapeTagBegin
func (decryptor *PgEscapeDecryptor) GetMatched() []byte {
	return EscapeTagBegin[:decryptor.currentIndex]
}

func (decryptor *PgEscapeDecryptor) readOctalData(data, octData []byte, reader io.Reader) (int, int, error) {
	dataIndex := 0
	octDataIndex := 0
	var charBuf [1]byte
	for {
		n, err := reader.Read(charBuf[:])
		if err != nil {
			return dataIndex, octDataIndex, err
		}
		if n != 1 {
			decryptor.logger.Debugln("readOctalData read 0 bytes")
			return dataIndex, octDataIndex, base.ErrFakeAcraStruct
		}
		octData[octDataIndex] = charBuf[0]
		octDataIndex++
		if !utils.IsPrintableEscapeChar(charBuf[0]) {
			return dataIndex, octDataIndex, base.ErrFakeAcraStruct
		}

		// if slash than next char must be slash too
		if charBuf[0] == utils.SlashChar {
			// read next char
			_, err := reader.Read(charBuf[:])
			if err != nil {
				return dataIndex, octDataIndex, err
			}
			octData[octDataIndex] = charBuf[0]
			octDataIndex++
			if charBuf[0] == utils.SlashChar {
				// just write slash char
				data[dataIndex] = charBuf[0]
				dataIndex++
			} else {
				decryptor.octCharBuf[0] = charBuf[0]
				// read next 3 oct bytes
				n, err := io.ReadFull(reader, decryptor.octCharBuf[1:])
				if err != nil {
					return dataIndex, octDataIndex, err
				}
				if n != len(decryptor.octCharBuf)-1 {
					if n != 0 {
						copy(octData[octDataIndex:octDataIndex+n], decryptor.octCharBuf[1:1+n])
						octDataIndex += n
					}
					decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingPostgresqlOctalEscape).Warningf("Expected 2 octal symbols, but read %v", n)
					return dataIndex, octDataIndex, base.ErrFakeAcraStruct
				}
				// parse 3 octal symbols
				num, err := strconv.ParseInt(string(decryptor.octCharBuf[:]), 8, 9)
				if err != nil {
					return dataIndex, octDataIndex, base.ErrFakeAcraStruct
				}
				data[dataIndex] = byte(num)
				dataIndex++

				copy(octData[octDataIndex:octDataIndex+len(decryptor.octCharBuf)-1], decryptor.octCharBuf[1:])
				octDataIndex += 2
			}
		} else {
			// just write to data
			data[dataIndex] = charBuf[0]
			dataIndex++
		}
		if dataIndex == cap(data) {
			return dataIndex, octDataIndex, nil
		}
	}
}

// ReadSymmetricKey decrypts symmetric key hidden in AcraStruct using SecureMessage and privateKey
// returns decrypted symmetric key or ErrFakeAcraStruct error if can't decrypt
func (decryptor *PgEscapeDecryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	dataLength, octDataLength, err := decryptor.readOctalData(decryptor.decodedKeyBlockBuffer, decryptor.octKeyBlockBuffer[:], reader)
	if err != nil {
		return nil, decryptor.octKeyBlockBuffer[:octDataLength], err
	}
	if len(decryptor.decodedKeyBlockBuffer) != base.KeyBlockLength || dataLength != base.KeyBlockLength {
		return nil, decryptor.octKeyBlockBuffer[:octDataLength], base.ErrFakeAcraStruct
	}
	smessage := message.New(privateKey, &keys.PublicKey{Value: decryptor.decodedKeyBlockBuffer[:base.PublicKeyLength]})
	symmetricKey, err := smessage.Unwrap(decryptor.decodedKeyBlockBuffer[base.PublicKeyLength:])
	if err != nil {
		return nil, decryptor.octKeyBlockBuffer[:octDataLength], base.ErrFakeAcraStruct
	}
	decryptor.outputSize += octDataLength
	return symmetricKey, decryptor.octKeyBlockBuffer[:octDataLength], nil
}

func (decryptor *PgEscapeDecryptor) readDataLength(reader io.Reader) (uint64, []byte, error) {
	var length uint64

	lenCount, octLenCount, err := decryptor.readOctalData(decryptor.lengthBuf[:], decryptor.octLengthBuf[:], reader)
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Warningln("Can't read data length")
		return 0, decryptor.octLengthBuf[:octLenCount], err
	}
	if lenCount != len(decryptor.lengthBuf) {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).Warningf("Incorrect length count, %v!=%v", lenCount, len(decryptor.lengthBuf))
		return 0, decryptor.octLengthBuf[:octLenCount], base.ErrFakeAcraStruct
	}
	decryptor.outputSize += octLenCount
	binary.Read(bytes.NewReader(decryptor.lengthBuf[:]), binary.LittleEndian, &length)
	return length, decryptor.octLengthBuf[:octLenCount], nil
}
func (decryptor *PgEscapeDecryptor) readScellData(length uint64, reader io.Reader) ([]byte, []byte, error) {
	hexBuf := make([]byte, length*4)
	buf := make([]byte, length)
	n, octN, err := decryptor.readOctalData(buf, hexBuf, reader)
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Warningf("Can't read scell data with passed length=%v", length)
		return nil, hexBuf[:octN], err
	}
	if uint64(n) != length {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).Warningf("Read incorrect length, %v!=%v", n, length)
		return nil, hexBuf[:octN], base.ErrFakeAcraStruct
	}
	decryptor.outputSize += octN
	return buf, hexBuf[:octN], nil
}

// ReadData returns plaintext content from reader data, decrypting using SecureCell with ZoneID and symmetricKey
func (decryptor *PgEscapeDecryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
	length, hexLengthBuf, err := decryptor.readDataLength(reader)
	if err != nil {
		return hexLengthBuf, err
	}
	data, octData, err := decryptor.readScellData(length, reader)
	if err != nil {
		return append(hexLengthBuf, octData...), err
	}

	scell := cell.New(symmetricKey, cell.ModeSeal)
	decrypted, err := scell.Unprotect(data, nil, zoneID)
	utils.ZeroizeSymmetricKey(symmetricKey)
	if err != nil {
		return append(hexLengthBuf, octData...), base.ErrFakeAcraStruct
	}
	return utils.EncodeToOctal(decrypted), nil
}

// GetTagBeginLength returns length of EscapeTagBegin
func (decryptor *PgEscapeDecryptor) GetTagBeginLength() int {
	return len(EscapeTagBegin)
}
