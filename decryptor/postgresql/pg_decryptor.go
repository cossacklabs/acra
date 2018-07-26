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
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/decryptor/base"
	acra_io "github.com/cossacklabs/acra/io"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	log "github.com/sirupsen/logrus"
)

// ReadForQuery - 'Z' ReadyForQuery, 0 0 0 5 length, 'I' idle status
// https://www.postgresql.org/docs/9.3/static/protocol-message-formats.html
var ReadyForQueryPacket = []byte{'Z', 0, 0, 0, 5, 'I'}

func NewPgError(message string) ([]byte, error) {
	// 5 = E marker + 4 bytes for message length
	// 7 is severity error with null terminator
	// +1 for null terminator of message and packet
	output := make([]byte, 5+7+7+len(message)+2)
	// error message
	output[0] = 'E'
	// leave untouched place for length of data
	output = output[:5]
	// error severity
	output = append(output, []byte{'S', 'E', 'R', 'R', 'O', 'R', 0}...)
	// 42000 - syntax_error_or_access_rule_violation
	// https://www.postgresql.org/docs/9.3/static/errcodes-appendix.html
	output = append(output, []byte("C42000")...)
	output = append(output, 0)
	// human readable message
	output = append(output, append([]byte{'M'}, []byte(message)...)...)
	output = append(output, 0, 0)
	// place length of data
	// -1 byte to exclude type of message
	// 1:5 4 bytes for packet length without first byte of message type
	binary.BigEndian.PutUint32(output[1:5], uint32(len(output)-1))
	return output, nil
}

type DataRow struct {
	messageType          [1]byte
	descriptionLengthBuf []byte
	descriptionBuf       *bytes.Buffer

	output            []byte
	columnSizePointer []byte
	columnDataBuf     *bytes.Buffer
	writeIndex        int
	columnCount       int
	dataLength        int
	errCh             chan<- error
	reader            *acra_io.ExtendedBufferedReader
	writer            *bufio.Writer
}

const (
	DATA_ROW_LENGTH_BUF_SIZE = 4
	// random chosen
	OUTPUT_DEFAULT_SIZE      = 1024
	COLUMN_DATA_DEFAULT_SIZE = 1024
	// https://www.postgresql.org/docs/9.4/static/protocol-message-formats.html
	DATA_ROW_MESSAGE_TYPE byte = 'D'
	QUERY_MESSAGE_TYPE    byte = 'Q'
	TLS_TIMEOUT                = time.Second
)

var CANCEL_REQUEST = []byte{0x04, 0xd2, 0x16, 0x2e}

/* override size in postgresql data row that starts with 4 byte of size */
func (packet *PacketHandler) SetDataSize(size int) {
	binary.BigEndian.PutUint32(packet.output[:DATA_ROW_LENGTH_BUF_SIZE], uint32(size+len(packet.descriptionLengthBuf)))
}

func (packet *PacketHandler) CheckOutputSize(size int) {
	availableSize := len(packet.output[packet.writeIndex:])
	if availableSize < size {
		newOutput := make([]byte, cap(packet.output)+(size-availableSize))
		copy(newOutput, packet.output)
		packet.output = newOutput
	}
}

func (packet *PacketHandler) skipData(reader io.Reader, writer io.Writer, errCh chan<- error) bool {
	packet.logger.Debugln("Read packet length")
	n, err := reader.Read(packet.descriptionLengthBuf)
	if !base.CheckReadWriteCh(n, 4, err, errCh) {
		return false
	}
	n2, err := io.Copy(writer, bytes.NewReader(packet.descriptionLengthBuf))
	if !base.CheckReadWriteCh(int(n2), 4, err, errCh) {
		return false
	}

	descriptionLength := int(binary.BigEndian.Uint32(packet.descriptionLengthBuf)) - len(packet.descriptionLengthBuf)
	packet.logger.WithField("length", packet.descriptionLengthBuf).WithField("length_value", descriptionLength).Debugln("Read packet data")
	n2, err = io.CopyN(writer, reader, int64(descriptionLength))
	if !base.CheckReadWriteCh(int(n2), descriptionLength, err, errCh) {
		return false
	}
	return true
}

func (packet *PacketHandler) readMessageType() error {
	packet.logger.Debugln("Read message type")
	n, err := packet.reader.Read(packet.messageType[:])
	if err := base.CheckReadWrite(n, 1, err); err != nil {
		return err
	}
	n, err = packet.writer.Write(packet.messageType[:])
	if err := base.CheckReadWrite(n, 1, err); err != nil {
		return err
	}
	packet.logger.Debugf("message_type - %s", string(packet.messageType[0]))
	return nil
}

func (packet *PacketHandler) IsDataRow() bool {
	return packet.messageType[0] == DATA_ROW_MESSAGE_TYPE
}

func (packet *PacketHandler) IsSimpleQuery() bool {
	return packet.messageType[0] == QUERY_MESSAGE_TYPE
}

func (packet *PacketHandler) UpdateColumnAndDataSize(oldColumnLength, newColumnLength int) bool {
	if oldColumnLength == newColumnLength {
		return true
	}
	// something was decrypted and size should be less that was before
	packet.logger.Debugf("Modify response size: %v -> %v", oldColumnLength, newColumnLength)

	// update column data size
	sizeDiff := oldColumnLength - newColumnLength
	packet.logger.Debugf("Old column size: %v; New column size: %v", oldColumnLength, newColumnLength)
	if newColumnLength > oldColumnLength {
		packet.errCh <- errors.New("decrypted size is more than encrypted")
		return false
	}
	binary.BigEndian.PutUint32(packet.columnSizePointer, uint32(newColumnLength))
	packet.logger.Debugf("Old data size: %v; new data size: %v", packet.dataLength, packet.dataLength-sizeDiff)
	// update data packet size
	packet.dataLength -= sizeDiff
	packet.SetDataSize(packet.dataLength)
	return true
}

func (packet *PacketHandler) ReadDataLength() bool {
	packet.logger.Debugln("Read data length")
	// read full data packet length
	n, err := packet.reader.Read(packet.output[:DATA_ROW_LENGTH_BUF_SIZE])
	if !base.CheckReadWriteCh(n, DATA_ROW_LENGTH_BUF_SIZE, err, packet.errCh) {
		return false
	}
	packet.writeIndex += n
	packet.dataLength = int(binary.BigEndian.Uint32(packet.output[:DATA_ROW_LENGTH_BUF_SIZE])) - len(packet.descriptionLengthBuf)
	return true
}

func (packet *PacketHandler) ReadColumnCount() bool {
	// read column count
	columnCountBuf := packet.output[DATA_ROW_LENGTH_BUF_SIZE : DATA_ROW_LENGTH_BUF_SIZE+2]
	n, err := packet.reader.Read(columnCountBuf)
	if !base.CheckReadWriteCh(n, 2, err, packet.errCh) {
		return false
	}
	packet.writeIndex += 2
	packet.columnCount = int(binary.BigEndian.Uint16(columnCountBuf))
	return true
}

func (packet *PacketHandler) Flush() bool {
	n, err := packet.writer.Write(packet.output[:packet.writeIndex])
	if !base.CheckReadWriteCh(n, packet.writeIndex, err, packet.errCh) {
		return false
	}
	if err := packet.writer.Flush(); err != nil {
		packet.logger.WithError(err).Errorln("Can't flush writer")
		packet.errCh <- err
		return false
	}
	return true
}

func (packet *PacketHandler) ReadData() ([]byte, bool) {
	packet.CheckOutputSize(packet.dataLength)
	n, err := packet.reader.Read(packet.output[packet.writeIndex : packet.writeIndex+packet.dataLength])
	if !base.CheckReadWriteCh(n, packet.dataLength, err, packet.errCh) {
		return nil, false
	}
	data := packet.output[packet.writeIndex : packet.writeIndex+packet.dataLength]
	packet.writeIndex += packet.dataLength
	return data, true
}

func (packet *PacketHandler) ReadSimpleQuery(errCh chan<- error) (string, bool) {
	packet.logger.Debugf("Read %v data", packet.dataLength)
	if !packet.ReadDataLength() {
		return "", false
	}
	query, success := packet.ReadData()
	return string(query), success
}

var ErrShortRead = errors.New("read less bytes than expected")

func (packet *PacketHandler) readData() error {
	packet.logger.Debugln("Read data length")
	n, err := packet.reader.Read(packet.descriptionLengthBuf)
	if err != nil {
		return err
	}
	if n != len(packet.descriptionLengthBuf) {
		return ErrShortRead
	}
	packet.dataLength = int(binary.BigEndian.Uint32(packet.descriptionLengthBuf)) - len(packet.descriptionLengthBuf)
	packet.descriptionBuf.Reset()
	packet.logger.Debugln("Read data")
	nn, err := io.CopyN(packet.descriptionBuf, packet.reader, int64(packet.dataLength))
	if err != nil {
		return err
	}
	if nn != int64(packet.dataLength) {
		return ErrShortRead
	}
	return nil
}

func (packet *PacketHandler) ReadPacket() (error) {
	packet.logger.Debugln("Read packet")
	if err := packet.readMessageType(); err != nil {
		return err
	}
	return packet.readData()
}

func (packet *PacketHandler) Marshal() ([]byte, error) {
	output := make([]byte, 0, 5+packet.dataLength)
	if packet.messageType[0] != 0 {
		output = append(output, packet.messageType[0])
	}
	output = append(output, packet.descriptionLengthBuf...)
	output = append(output, packet.descriptionBuf.Bytes()...)
	return output, nil
}

type PgProxy struct {
	clientConnection net.Conn
	dbConnection     net.Conn
	TlsCh            chan bool
}

func NewPgProxy(clientConnection, dbConnection net.Conn) (*PgProxy, error) {
	return &PgProxy{clientConnection: clientConnection, dbConnection: dbConnection, TlsCh: make(chan bool)}, nil
}

func (proxy *PgProxy) PgProxyClientRequests(acraCensor acracensor.AcraCensorInterface, dbConnection, clientConnection net.Conn, errCh chan<- error) {
	logger := log.WithField("proxy", "pg_client")
	logger.Debugln("Pg client proxy")
	writer := bufio.NewWriter(dbConnection)

	reader := acra_io.NewExtendedBufferedReader(bufio.NewReader(clientConnection))
	packet, err := NewClientSidePacketHandler(reader, writer)
	if err != nil {
		logger.WithError(err).Errorln("Can't initialize DataRow object")
		errCh <- err
		return
	}
	for {
		packet.descriptionBuf.Reset()
		err := packet.ReadPacket()
		if err != nil {
			logger.WithError(err).Errorln("Can't read packet")
			errCh <- err
			return
		}
		if !packet.IsSimpleQuery() {
			if err := packet.sendPacket(); err != nil {
				logger.WithError(err).Errorln("Can't forward packet to db")
				errCh <- err
				return
			}
			continue
		}

		query := string(packet.descriptionBuf.Bytes()[:packet.dataLength-1])
		logger.WithField("query", query).Debugln("New query")
		if censorErr := acraCensor.HandleQuery(query); censorErr != nil {
			logger.WithError(censorErr).Errorln("AcraCensor blocked query")
			errorMessage, err := NewPgError("AcraCensor blocked this query")
			if err != nil {
				logger.WithError(err).Errorln("Can't create postgresql error message")
				errCh <- err
				return
			}
			n, err := clientConnection.Write(errorMessage)
			if !base.CheckReadWriteCh(n, len(errorMessage), err, errCh) {
				return
			}
			n, err = clientConnection.Write(ReadyForQueryPacket)
			if !base.CheckReadWriteCh(n, len(ReadyForQueryPacket), err, errCh) {
				return
			}
			continue
		}

		if err := packet.sendPacket(); err != nil {
			logger.WithError(err).Errorln("Can't send packet")
			errCh <- err
			return
		}
	}
}

func (packet *PacketHandler) IsSSLRequestAllowed() bool {
	return packet.messageType[0] == 'S'
}

func (packet *PacketHandler) IsSSLRequestDeny() bool {
	return packet.messageType[0] == 'N'
}

func (proxy *PgProxy) checkPoisonRecordBlock(data []byte, decryptor base.Decryptor) error {
	if decryptor.IsPoisonRecordCheckOn(){
		// check on poison record
		if err := base.ValidateAcraStructLength(data); err == nil {
			poisoned, err := decryptor.CheckPoisonRecord(bytes.NewReader(data))
			if err != nil {
				log.WithError(err).Errorln("Can't check on poison record")
				return err
			}
			if poisoned {
				// TODO check that message the same as in other places
				log.Warningln("Recognized poison record")
				callbacks := decryptor.GetPoisonCallbackStorage()
				if callbacks.HasCallbacks(){
					var callbackErr error
					if err := callbacks.Call(); err != nil {
						log.WithError(err).Errorln("Unexpected error on poison record callback")
						callbackErr = err
					}
					if callbackErr != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (proxy *PgProxy) processWholeBlockDecryption(column *ColumnData, decryptor base.Decryptor) error {
	if decryptor.IsWithZone() && !decryptor.IsMatchedZone(){
		decryptor.MatchZoneBlock(column.Data)
		if decryptor.IsPoisonRecordCheckOn(){
			// check on poison record
			if err := base.ValidateAcraStructLength(column.Data); err == nil {
				poisoned, err := decryptor.CheckPoisonRecord(bytes.NewReader(column.Data))
				if err != nil {
					log.WithError(err).Errorln("Can't check on poison record")
					return err
				}
				if poisoned {
					// TODO check that message the same as in other places
					log.Warningln("Recognized poison record")
					callbacks := decryptor.GetPoisonCallbackStorage()
					if callbacks.HasCallbacks(){
						var callbackErr error
						if err := callbacks.Call(); err != nil {
							log.WithError(err).Errorln("Unexpected error on poison record callback")
							callbackErr = err
						}
						if callbackErr != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	}
	if err := base.ValidateAcraStructLength(column.Data); err != nil {
		continue
	}
	decrypted, err := decryptor.DecryptBlock(column.Data)
	if err != nil {

		continue
	}
	// poison record check
	// check only if has any action on detection
	if decryptor.IsPoisonRecordCheckOn() {
		logger.Debugln("Check poison records")
		block, err := decryptor.SkipBeginInBlock(packet.output[packet.writeIndex : packet.writeIndex+columnDataLength])
		if err == nil {
			_, err := decryptor.CheckPoisonRecord(bytes.NewReader(block))
			if err != nil {
				logger.WithError(err).Errorln("Error on check poison record")
				errCh <- err
				return
			}
		}
	}
	// end poison record check

	decryptor.Reset()
	if !decryptor.IsWithZone() || decryptor.IsMatchedZone() {
		decrypted, err := decryptor.DecryptBlock(packet.output[packet.writeIndex : packet.writeIndex+columnDataLength])
		if err == nil {
			copy(packet.output[packet.writeIndex:], decrypted)
			packet.UpdateColumnAndDataSize(columnDataLength, len(decrypted))
			packet.writeIndex += len(decrypted)
			continue
		} else if err == base.ErrPoisonRecord {
			logger.Errorln("Poison record detected")
			errCh <- err
			return
		}
	} else {
		decryptor.MatchZoneBlock(packet.output[packet.writeIndex : packet.writeIndex+columnDataLength])
	}
	packet.writeIndex += columnDataLength
}

func (proxy *PgProxy) PgDecryptStream(censor acracensor.AcraCensorInterface, decryptor base.Decryptor, tlsConfig *tls.Config, dbConnection net.Conn, clientConnection net.Conn, errCh chan<- error) {
	logger := log.WithField("proxy", "db_size")
	logger.Debugln("Pg db proxy")
	writer := bufio.NewWriter(clientConnection)

	reader := acra_io.NewExtendedBufferedReader(bufio.NewReader(dbConnection))
	packet := PacketHandler{
		writeIndex:           0,
		output:               make([]byte, OUTPUT_DEFAULT_SIZE),
		columnDataBuf:        bytes.NewBuffer(make([]byte, COLUMN_DATA_DEFAULT_SIZE)),
		descriptionLengthBuf: make([]byte, 4),
		reader:               reader,
		writer:               writer,
		logger:               logger,
	}
	firstByte := true
	for {
		if err := packet.ReadPacket(); err != nil {
			logger.WithError(err).Errorln("Can't read packet")
			errCh <- err
			return
		}
		if firstByte {
			// https://www.postgresql.org/docs/9.1/static/protocol-flow.html#AEN92112
			// we should know that we shouldn't read anymore bytes
			firstByte = false
			if packet.IsSSLRequestDeny() {
				logger.Debugln("Deny ssl request")
				if err := packet.sendMessageType(); err != nil {
					errCh <- err
					return
				}
				continue
			} else if packet.IsSSLRequestAllowed() {
				if tlsConfig == nil {
					logger.Errorln("To support TLS connections you must pass TLS key and certificate for AcraServer that will be used" +
						"for connections AcraServer->Database and CA certificate which will be used to verify certificate " +
						"from database")
					errCh <- network.ErrEmptyTLSConfig
					return
				}
				logger.Debugln("Start tls proxy")
				// stop reading from client in goroutine
				if err := clientConnection.SetDeadline(time.Now()); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
						Errorln("Can't set deadline")
					errCh <- err
					return
				}
				select {
				case <-proxy.TlsCh:
					break
				case <-time.NewTimer(TLS_TIMEOUT).C:
					logger.Errorln("Can't stop background goroutine to start tls handshake")
					errCh <- errors.New("can't stop background goroutine")
					return
				}
				logger.Debugln("Stop client connection")
				if err := clientConnection.SetDeadline(time.Time{}); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
						Errorln("Can't set deadline")
					errCh <- err
					return
				}
				logger.Debugln("Init tls with client")
				// convert to tls connection
				tlsClientConnection := tls.Server(clientConnection, tlsConfig)

				if err := packet.sendMessageType(); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Can't send ssl allow packet")
					errCh <- err
					return
				}
				if err := tlsClientConnection.Handshake(); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Can't initialize tls connection with client")
					errCh <- err
					return
				}

				logger.Debugln("Init tls with db")
				dbTLSConnection := tls.Client(dbConnection, tlsConfig)
				if err := dbTLSConnection.Handshake(); err != nil {
					logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Can't initialize tls connection with db")
					errCh <- err
					return
				}

				// restart proxing client's requests
				go proxy.PgProxyClientRequests(censor, dbTLSConnection, tlsClientConnection, errCh)
				reader = acra_io.NewExtendedBufferedReader(bufio.NewReader(dbTLSConnection))
				writer = bufio.NewWriter(tlsClientConnection)
				firstByte = true

				packet.reader = reader
				packet.writer = writer
				packet.firstPacket = false
				packet.messageType[0] = 0
				continue
			}
		}

		if !packet.IsDataRow() {
			if err := packet.sendPacket(); err != nil{
				logger.WithError(err).Errorln("Can't forward packet")
				errCh <- err
				return
			}
			continue
		}

		logger.Debugln("Matched data packet")
		if err := packet.parseColumns(); err != nil {
			errCh <- err
			return
		}

		if packet.columnCount == 0 {
			if err := packet.sendPacket(); err != nil {
				errCh <- err
				return
			}
			continue
		}

		logger.Debugf("Process columns data")
		for i := 0; i < packet.columnCount; i++ {
			column := packet.Columns[i]

			// TODO check poison record before zone matching in two modes.
			// now zone matching executed every time
			// try to skip small piece of data that can't be valuable for us
			if (decryptor.IsWithZone() && column.Length() >= zone.ZONE_ID_BLOCK_LENGTH) || column.Length() >= base.KEY_BLOCK_LENGTH {
				decryptor.Reset()
				if decryptor.IsWholeMatch() {
					err := proxy.processWholeBlockDecryption(column decryptor)
				} else {
					currentIndex := packet.writeIndex
					endIndex := packet.writeIndex + columnDataLength

					// check poison records
					if decryptor.IsPoisonRecordCheckOn() {
						logger.Debugln("Check poison records")
						for {
							beginTagIndex, tagLength := decryptor.BeginTagIndex(packet.output[currentIndex:endIndex])
							if beginTagIndex == utils.NOT_FOUND {
								logger.Debugln("Not found begin tag")
								break
							}
							logger.Debugln("Found begin tag")
							blockReader := bytes.NewReader(packet.output[currentIndex+beginTagIndex+tagLength:])
							_, err := decryptor.CheckPoisonRecord(blockReader)
							if err != nil {
								logger.WithError(err).Errorln("Error on check poison record")
								errCh <- err
								return
							}
							// try to find after founded tag with offset
							currentIndex += beginTagIndex + 1
						}
					}
					if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
						decryptor.MatchZoneInBlock(packet.output[packet.writeIndex : packet.writeIndex+columnDataLength])
						packet.writeIndex += columnDataLength
						continue
					}
					currentIndex = packet.writeIndex
					halted := false
					for {
						beginTagIndex, tagLength := decryptor.BeginTagIndex(packet.output[currentIndex:endIndex])
						if beginTagIndex == utils.NOT_FOUND {
							packet.columnDataBuf.Write(packet.output[currentIndex:endIndex])
							break
						}
						// convert to absolute index
						beginTagIndex += currentIndex
						packet.columnDataBuf.Write(packet.output[currentIndex:beginTagIndex])
						currentIndex = beginTagIndex

						key, err := decryptor.GetPrivateKey()
						if err != nil {
							logger.Warningln("Can't read private key")
							halted = true
							break
						}
						blockReader := bytes.NewReader(packet.output[beginTagIndex+tagLength:])
						symKey, _, err := decryptor.ReadSymmetricKey(key, blockReader)
						if err != nil {
							logger.Warningf("%v", utils.ErrorMessage("Can't unwrap symmetric key", err))
							packet.columnDataBuf.Write([]byte{packet.output[currentIndex]})
							currentIndex++
							continue
						}
						data, err := decryptor.ReadData(symKey, decryptor.GetMatchedZoneID(), blockReader)
						if err != nil {
							logger.Warningf("%v", utils.ErrorMessage("Can't decrypt data with unwrapped symmetric key", err))
							packet.columnDataBuf.Write([]byte{packet.output[currentIndex]})
							currentIndex++
							continue
						}
						packet.columnDataBuf.Write(data)
						currentIndex += tagLength + (len(packet.output[beginTagIndex+tagLength:]) - blockReader.Len())
					}
					if !halted && packet.columnDataBuf.Len() < columnDataLength {
						logger.Debugln("Result was changed")
						copy(packet.output[packet.writeIndex:], packet.columnDataBuf.Bytes())
						packet.writeIndex += packet.columnDataBuf.Len()
						packet.UpdateColumnAndDataSize(columnDataLength, packet.columnDataBuf.Len())
						decryptor.ResetZoneMatch()
					} else {
						logger.Debugln("Result was not changed")
						packet.writeIndex = endIndex
					}
				}
			} else {
				logger.Debugln("Skip decryption")
				packet.writeIndex += columnDataLength
			}
		}
		logger.Debugln("packet flush")
		if !packet.Flush() {
			return
		}
		decryptor.Reset()
		decryptor.ResetZoneMatch()
	}
}
