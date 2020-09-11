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

// Package binary contains Decryptor, that finds and decrypts AcraStruct from any binary blobs.
package binary

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/cossacklabs/themis/gothemis/message"
	log "github.com/sirupsen/logrus"
)

// Decryptor stores settings for finding and decrypting AcraStruct from binary data
type Decryptor struct {
	currentIndex   uint8
	keyBlockBuffer []byte
	lengthBuf      [base.DataLengthSize]byte
	buf            []byte
	logger         *log.Entry
}

// NewBinaryDecryptor returns new Decryptor
func NewBinaryDecryptor(logger *log.Entry) *Decryptor {
	return &Decryptor{keyBlockBuffer: make([]byte, base.KeyBlockLength), logger: logger}
}

// SetLogger set logger
func (decryptor *Decryptor) SetLogger(logger *log.Entry) {
	decryptor.logger = logger
}

// MatchBeginTag not implemented Decryptor interface
func (decryptor *Decryptor) MatchBeginTag(char byte) bool {
	if char == base.TagBegin[decryptor.currentIndex] {
		decryptor.currentIndex++
		return true
	}
	return false
}

// IsMatched returns true if AcraStruct BeginTag found
func (decryptor *Decryptor) IsMatched() bool {
	return len(base.TagBegin) == int(decryptor.currentIndex)
}

// Reset pointer on current Index of binary data
func (decryptor *Decryptor) Reset() {
	decryptor.currentIndex = 0
}

// GetMatched returns bytes from binary data that match with AcraStruct BeginTag
func (decryptor *Decryptor) GetMatched() []byte {
	return base.TagBegin[:decryptor.currentIndex]
}

// ReadSymmetricKey returns symmetric key wrapped in AcraStruct
func (decryptor *Decryptor) ReadSymmetricKey(privateKey *keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	n, err := io.ReadFull(reader, decryptor.keyBlockBuffer[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.keyBlockBuffer[:n], err
	}
	pubkey := &keys.PublicKey{Value: decryptor.keyBlockBuffer[:base.PublicKeyLength]}

	smessage := message.New(privateKey, pubkey)
	symmetricKey, err := smessage.Unwrap(decryptor.keyBlockBuffer[base.PublicKeyLength:])
	if err != nil {
		return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
	}
	return symmetricKey, decryptor.keyBlockBuffer[:n], nil
}

// ReadSymmetricKeyRotated returns symmetric key wrapped in AcraStruct trying multiple private keys.
func (decryptor *Decryptor) ReadSymmetricKeyRotated(privateKeys []*keys.PrivateKey, reader io.Reader) ([]byte, []byte, error) {
	n, err := io.ReadFull(reader, decryptor.keyBlockBuffer[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.keyBlockBuffer[:n], err
	}
	pubkey := &keys.PublicKey{Value: decryptor.keyBlockBuffer[:base.PublicKeyLength]}

	for _, privateKey := range privateKeys {
		smessage := message.New(privateKey, pubkey)
		symmetricKey, err := smessage.Unwrap(decryptor.keyBlockBuffer[base.PublicKeyLength:])
		if err == nil {
			return symmetricKey, decryptor.keyBlockBuffer[:n], nil
		}
	}
	return nil, decryptor.keyBlockBuffer[:n], base.ErrFakeAcraStruct
}

func (decryptor *Decryptor) readDataLength(reader io.Reader) (uint64, []byte, error) {
	var length uint64
	lenCount, err := io.ReadFull(reader, decryptor.lengthBuf[:])
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Warningln("Can't read data length")
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return uint64(lenCount), decryptor.lengthBuf[:lenCount], base.ErrFakeAcraStruct
		}
		return 0, []byte{}, err
	}
	if lenCount != len(decryptor.lengthBuf) {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).Warningf("Incorrect length count, %v!=%v", lenCount, len(decryptor.lengthBuf))
		return 0, decryptor.lengthBuf[:lenCount], base.ErrFakeAcraStruct
	}
	// convert from little endian
	binary.Read(bytes.NewReader(decryptor.lengthBuf[:]), binary.LittleEndian, &length)
	return length, decryptor.lengthBuf[:], nil
}

func (decryptor *Decryptor) checkBuf(buf *[]byte, length uint64) {
	if buf == nil || uint64(len(*buf)) < length {
		*buf = make([]byte, length)
	}
}

func (decryptor *Decryptor) readScellData(length uint64, reader io.Reader) ([]byte, []byte, error) {
	decryptor.checkBuf(&decryptor.buf, length)
	n, err := io.ReadFull(reader, decryptor.buf[:length])
	if err != nil {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorReadPacket).WithError(err).Warningf("Can't read scell data with passed length=%v", length)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, decryptor.buf[:n], base.ErrFakeAcraStruct
		}
		return nil, decryptor.buf[:n], err
	}
	if uint64(n) != length {
		decryptor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeHexData).WithError(err).Warningln("Can't decode hex data")
		return nil, decryptor.buf[:n], base.ErrFakeAcraStruct
	}
	return decryptor.buf[:length], decryptor.buf[:length], nil
}

// ReadData decrypts encrypted content of AcraStruct using Symmetric key and Zone
func (decryptor *Decryptor) ReadData(symmetricKey, zoneID []byte, reader io.Reader) ([]byte, error) {
	length, rawLengthData, err := decryptor.readDataLength(reader)
	if err != nil {
		return rawLengthData, err
	}
	data, rawData, err := decryptor.readScellData(length, reader)
	if err != nil {
		return append(rawLengthData, rawData...), err
	}

	scell := cell.New(symmetricKey, cell.ModeSeal)
	decrypted, err := scell.Unprotect(data, nil, zoneID)

	// fill zero symmetric_key
	utils.FillSlice(byte(0), symmetricKey)
	if err != nil {
		return append(rawLengthData, rawData...), base.ErrFakeAcraStruct
	}
	return decrypted, nil
}

// GetTagBeginLength returns length of AcraStruct BeginTag
func (*Decryptor) GetTagBeginLength() int {
	return len(base.TagBegin)
}
