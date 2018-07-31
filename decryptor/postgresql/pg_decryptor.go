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

func (packet *PacketHandler) readMessageType() error {
	n, err := packet.reader.Read(packet.messageType[:])
	if err := base.CheckReadWrite(n, 1, err); err != nil {
		return err
	}
	return nil
}

func (packet *PacketHandler) IsDataRow() bool {
	return packet.messageType[0] == DATA_ROW_MESSAGE_TYPE
}

func (packet *PacketHandler) IsSimpleQuery() bool {
	return packet.messageType[0] == QUERY_MESSAGE_TYPE
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
	packet.descriptionBuf.Grow(packet.dataLength)
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

func (packet *PacketHandler) ReadPacket() error {
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
	firstPacket := true
	for {
		packet.descriptionBuf.Reset()
		if firstPacket {
			err = packet.readData()
			firstPacket = false
		} else {
			err = packet.ReadPacket()
		}
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

func handlePoisonCheckResult(decryptor base.Decryptor, poisoned bool, err error) error {
	if err != nil {
		log.WithError(err).Errorln("Can't check on poison record")
		return err
	}
	if poisoned {
		log.Warningln("Recognized poison record")
		callbacks := decryptor.GetPoisonCallbackStorage()
		if callbacks.HasCallbacks() {
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
	return nil
}

func checkPoisonRecordInBlock(block []byte, decryptor base.Decryptor) error {
	// check is it Poison Record
	if decryptor.IsPoisonRecordCheckOn() {
		log.Debugln("Check poison records")
		if index, length := decryptor.BeginTagIndex(block); index != utils.NOT_FOUND {
			poisoned, err := decryptor.CheckPoisonRecord(bytes.NewReader(block[index+length:]))
			return handlePoisonCheckResult(decryptor, poisoned, err)
		}
	}
	return nil
}

func (proxy *PgProxy) processWholeBlockDecryption(packet *PacketHandler, column *ColumnData, decryptor base.Decryptor) error {
	decryptor.Reset()
	decrypted, err := decryptor.DecryptBlock(column.Data)
	if err != nil {
		log.WithError(err).Errorln("Can't decrypt possible AcraStruct")
		if decryptor.IsPoisonRecordCheckOn() {
			decryptor.Reset()
			skippedBegin, err := decryptor.SkipBeginInBlock(column.Data)
			if err != nil {
				log.WithError(err).Errorln("Can't skip begin tag for poison record check")
				return nil
			}
			poisoned, checkErr := decryptor.CheckPoisonRecord(bytes.NewReader(skippedBegin))
			if innerErr := handlePoisonCheckResult(decryptor, poisoned, checkErr); err != nil {
				log.WithError(innerErr).Errorln("Error on poison record check")
				return innerErr
			}
		}
		return nil
	}
	column.SetData(decrypted)
	return nil
}

// PgDecryptStream process data rows from database
func (proxy *PgProxy) PgDecryptStream(censor acracensor.AcraCensorInterface, decryptor base.Decryptor, tlsConfig *tls.Config, dbConnection net.Conn, clientConnection net.Conn, errCh chan<- error) {
	logger := log.WithField("proxy", "db_side")
	logger.Debugln("Pg db proxy")
	writer := bufio.NewWriter(clientConnection)

	reader := acra_io.NewExtendedBufferedReader(bufio.NewReader(dbConnection))
	packet, err := NewDbSidePacketHandler(reader, writer)
	if err != nil {
		errCh <- err
		return
	}

	firstByte := true
	for {
		if firstByte {
			// https://www.postgresql.org/docs/9.1/static/protocol-flow.html#AEN92112
			// we should know that we shouldn't read anymore bytes
			firstByte = false
			if err := packet.readMessageType(); err != nil {
				logger.WithError(err).Errorln("Can't read first message type")
				errCh <- err
				return
			}
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
			if err := packet.readData(); err != nil {
				logger.WithError(err).Errorln("Can't read data of packet")
				errCh <- err
				return
			}
			if err := packet.sendPacket(); err != nil {
				logger.WithError(err).Errorln("Can't forward first packet")
				errCh <- err
				return
			}
			continue
		}

		if err := packet.ReadPacket(); err != nil {
			logger.WithError(err).Errorln("Can't read packet")
			errCh <- err
			return
		}

		if !packet.IsDataRow() {
			if err := packet.sendPacket(); err != nil {
				logger.WithError(err).Errorln("Can't forward packet")
				errCh <- err
				return
			}
			continue
		}

		logger.Debugln("Matched data packet")
		if err := packet.parseColumns(); err != nil {
			logger.WithError(err).Errorln("Can't parse columns in packet")
			errCh <- err
			return
		}

		if packet.columnCount == 0 {
			if err := packet.sendPacket(); err != nil {
				logger.WithError(err).Errorln("Can't send packet on column count 0")
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

				// Zone anyway should be passed as whole block
				// so try to match before any operations if we process with ZoneMode on
				if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
					// try to match zone
					decryptor.MatchZoneBlock(column.Data)
					// check that it's not poison record
					err := checkPoisonRecordInBlock(column.Data, decryptor)
					if err != nil {
						logger.WithError(err).Errorln("Can't check poison record in block")
						errCh <- err
						return
					}
					continue
				}

				if decryptor.IsWholeMatch() {
					err := proxy.processWholeBlockDecryption(packet, column, decryptor)
					if err != nil {
						log.WithError(err).Errorln("Can't process whole block")
						errCh <- err
						return
					}
				} else {
					// inline mode
					currentIndex := 0
					endIndex := column.Length()
					outputBlock := bytes.NewBuffer(make([]byte, 0, column.Length()))
					hasDecryptedData := false
					for {
						beginTagIndex, tagLength := decryptor.BeginTagIndex(column.Data[currentIndex:endIndex])
						if beginTagIndex == utils.NOT_FOUND {
							// no AcraStructs in column decryptedData
							break
						}
						// convert to absolute index
						beginTagIndex += currentIndex
						// write data before start of AcraStruct
						outputBlock.Write(column.Data[currentIndex:beginTagIndex])
						currentIndex = beginTagIndex

						key, err := decryptor.GetPrivateKey()
						if err != nil {
							logger.WithError(err).Warningln("Can't read private key")
							continue
						}
						blockReader := bytes.NewReader(column.Data[beginTagIndex+tagLength:])
						symKey, _, err := decryptor.ReadSymmetricKey(key, blockReader)
						if err != nil {
							logger.WithError(err).Warningln("Can't unwrap symmetric key")
							if decryptor.IsPoisonRecordCheckOn() {
								log.Infoln("Check poison records")
								blockReader = bytes.NewReader(column.Data[beginTagIndex+tagLength:])
								poisoned, err := decryptor.CheckPoisonRecord(blockReader)
								err = handlePoisonCheckResult(decryptor, poisoned, err)
								if err != nil {
									logger.WithError(err).Errorln("Error on poison record processing")
									errCh <- err
									return
								}
							}

							// write current read byte to not process him in next iteration
							outputBlock.Write([]byte{column.Data[currentIndex]})
							currentIndex++
							continue
						}
						decryptedData, err := decryptor.ReadData(symKey, decryptor.GetMatchedZoneID(), blockReader)
						if err != nil {

							logger.WithError(err).Warningln("Can't decrypt data with unwrapped symmetric key")
							// write current read byte to not process him in next iteration
							outputBlock.Write([]byte{packet.output[currentIndex]})
							currentIndex++
							continue
						}
						outputBlock.Write(decryptedData)
						currentIndex += tagLength + (len(column.Data[beginTagIndex+tagLength:]) - blockReader.Len())
						hasDecryptedData = true
					}
					if hasDecryptedData {
						logger.WithFields(log.Fields{"old_size": column.Length(), "new_size": outputBlock.Len()}).Debugln("Result was changed")
						column.SetData(outputBlock.Bytes())
						decryptor.ResetZoneMatch()
						decryptor.Reset()
					} else {
						logger.Debugln("Result was not changed")
						packet.writeIndex = endIndex
					}
				}
			} else {
				logger.Debugln("Skip decryption because length of block too small for ZoneId or AcraStruct")
			}
		}
		packet.updateDataFromColumns()
		logger.Debugln("send packet")
		if err := packet.sendPacket(); err != nil {
			logger.WithError(err).Errorln("Can't send packet")
			errCh <- err
			return
		}
		decryptor.Reset()
		decryptor.ResetZoneMatch()
	}
}
