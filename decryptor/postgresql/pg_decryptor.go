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
func (row *DataRow) SetDataSize(size int) {
	binary.BigEndian.PutUint32(row.output[:DATA_ROW_LENGTH_BUF_SIZE], uint32(size+len(row.descriptionLengthBuf)))
}

func (row *DataRow) CheckOutputSize(size int) {
	availableSize := len(row.output[row.writeIndex:])
	if availableSize < size {
		newOutput := make([]byte, cap(row.output)+(size-availableSize))
		copy(newOutput, row.output)
		row.output = newOutput
	}
}

func (row *DataRow) skipData(reader io.Reader, writer io.Writer, errCh chan<- error) bool {
	log.Debugln("read row length")
	n, err := reader.Read(row.descriptionLengthBuf)
	if !base.CheckReadWrite(n, 4, err, errCh) {
		return false
	}
	n2, err := io.Copy(writer, bytes.NewReader(row.descriptionLengthBuf))
	if !base.CheckReadWrite(int(n2), 4, err, errCh) {
		return false
	}

	descriptionLength := int(binary.BigEndian.Uint32(row.descriptionLengthBuf)) - len(row.descriptionLengthBuf)
	log.WithField("length", row.descriptionLengthBuf).WithField("length_value", descriptionLength).Debugln("read row data")
	n2, err = io.CopyN(writer, reader, int64(descriptionLength))
	if !base.CheckReadWrite(int(n2), descriptionLength, err, errCh) {
		return false
	}
	return true
}

func (row *DataRow) readMessageType(reader io.Reader, writer io.Writer, errCh chan<- error) bool {
	n, err := reader.Read(row.messageType[:])
	if !base.CheckReadWrite(n, 1, err, errCh) {
		return false
	}
	n, err = writer.Write(row.messageType[:])
	if !base.CheckReadWrite(n, 1, err, errCh) {
		return false
	}
	return true
}

func (row *DataRow) IsDataRow() bool {
	return row.messageType[0] == DATA_ROW_MESSAGE_TYPE
}

func (row *DataRow) IsSimpleQuery() bool {
	return row.messageType[0] == QUERY_MESSAGE_TYPE
}

func (row *DataRow) UpdateColumnAndDataSize(oldColumnLength, newColumnLength int) bool {
	if oldColumnLength == newColumnLength {
		return true
	}
	// something was decrypted and size should be less that was before
	log.Debugf("Modify response size: %v -> %v", oldColumnLength, newColumnLength)

	// update column data size
	sizeDiff := oldColumnLength - newColumnLength
	log.Debugf("Old column size: %v; New column size: %v", oldColumnLength, newColumnLength)
	if newColumnLength > oldColumnLength {
		row.errCh <- errors.New("decrypted size is more than encrypted")
		return false
	}
	binary.BigEndian.PutUint32(row.columnSizePointer, uint32(newColumnLength))
	log.Debugf("Old data size: %v; new data size: %v", row.dataLength, row.dataLength-sizeDiff)
	// update data row size
	row.dataLength -= sizeDiff
	row.SetDataSize(row.dataLength)
	return true
}

func (row *DataRow) ReadDataLength() bool {
	log.Debugln("Read data length")
	// read full data row length
	n, err := row.reader.Read(row.output[:DATA_ROW_LENGTH_BUF_SIZE])
	if !base.CheckReadWrite(n, DATA_ROW_LENGTH_BUF_SIZE, err, row.errCh) {
		return false
	}
	row.writeIndex += n
	row.dataLength = int(binary.BigEndian.Uint32(row.output[:DATA_ROW_LENGTH_BUF_SIZE])) - len(row.descriptionLengthBuf)
	return true
}

func (row *DataRow) ReadColumnCount() bool {
	// read column count
	columnCountBuf := row.output[DATA_ROW_LENGTH_BUF_SIZE : DATA_ROW_LENGTH_BUF_SIZE+2]
	n, err := row.reader.Read(columnCountBuf)
	if !base.CheckReadWrite(n, 2, err, row.errCh) {
		return false
	}
	row.writeIndex += 2
	row.columnCount = int(binary.BigEndian.Uint16(columnCountBuf))
	return true
}

func (row *DataRow) Flush() bool {
	n, err := row.writer.Write(row.output[:row.writeIndex])
	if !base.CheckReadWrite(n, row.writeIndex, err, row.errCh) {
		return false
	}
	if err := row.writer.Flush(); err != nil {
		log.WithError(err).Errorln("can't flush writer")
		row.errCh <- err
		return false
	}
	return true
}

func (row *DataRow) ReadData() ([]byte, bool) {
	row.CheckOutputSize(row.dataLength)
	n, err := row.reader.Read(row.output[row.writeIndex : row.writeIndex+row.dataLength])
	if !base.CheckReadWrite(n, row.dataLength, err, row.errCh) {
		return nil, false
	}
	data := row.output[row.writeIndex : row.writeIndex+row.dataLength]
	row.writeIndex += row.dataLength
	return data, true
}

func (row *DataRow) ReadSimpleQuery(errCh chan<- error) (string, bool) {
	log.Debugf("read %v data", row.dataLength)
	if !row.ReadDataLength() {
		return "", false
	}
	query, success := row.ReadData()
	return string(query), success
}

var ErrShortRead = errors.New("read less bytes than expected")

func (row *DataRow) ReadRow(reader io.Reader, errCh chan<- error) (*DataRow, error) {
	n, err := reader.Read(row.messageType[:])
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrShortRead
	}
	n, err = reader.Read(row.descriptionLengthBuf)
	if err != nil {
		return nil, err
	}
	if n != len(row.descriptionLengthBuf) {
		return nil, ErrShortRead
	}
	row.dataLength = int(binary.BigEndian.Uint32(row.descriptionLengthBuf)) - len(row.descriptionLengthBuf)
	row.descriptionBuf.Reset()
	nn, err := io.CopyN(row.descriptionBuf, reader, int64(row.dataLength))
	if err != nil {
		return nil, err
	}
	if nn != int64(row.dataLength) {
		return nil, ErrShortRead
	}
	return row, nil
}

func (row *DataRow) Marshal() ([]byte, error) {
	output := make([]byte, 0, 5+row.dataLength)
	output = append(output, row.messageType[0])
	output = append(output, row.descriptionLengthBuf...)
	output = append(output, row.descriptionBuf.Bytes()...)
	return output, nil
}

type PgProxy struct {
	clientConnection net.Conn
	dbConnection     net.Conn
	errCh            chan<- error
	TlsCh            chan bool
}

func NewPgProxy(clientConnection, dbConnection net.Conn, errCh chan<- error) (*PgProxy, error) {
	return &PgProxy{clientConnection: clientConnection, dbConnection: dbConnection, errCh: errCh, TlsCh: make(chan bool)}, nil
}

func NewClientSideDataRow(reader *acra_io.ExtendedBufferedReader, writer *bufio.Writer) (*DataRow, error) {
	return &DataRow{
		writeIndex:           0,
		output:               nil,
		columnDataBuf:        nil,
		descriptionBuf:       bytes.NewBuffer(make([]byte, OUTPUT_DEFAULT_SIZE)),
		descriptionLengthBuf: make([]byte, 4),
		reader:               reader,
		writer:               writer,
	}, nil
}

func (proxy *PgProxy) PgProxyClientRequests(acraCensor acracensor.AcraCensorInterface, dbConnection, clientConnection net.Conn, errCh chan<- error) {
	log.Debugln("pg client proxy")
	writer := bufio.NewWriter(dbConnection)

	reader := acra_io.NewExtendedBufferedReader(bufio.NewReader(clientConnection))
	row, err := NewClientSideDataRow(reader, writer)
	if err != nil {
		log.WithError(err).Errorln("can't initialize DataRow object")
		errCh <- err
		return
	}
	firstByte := true
	for {
		row.descriptionBuf.Reset()
		if firstByte {
			log.Debugln("first packet")
			// first packet hasn't type of message and start with message length and data
			firstByte = false
			if !row.skipData(reader, writer, errCh) {
				return
			}
			if err := writer.Flush(); err != nil {
				log.WithError(err).Errorln("can't flush writer")
				errCh <- err
				return
			}
			continue
		}
		row, err := row.ReadRow(reader, errCh)
		if err != nil {
			log.WithError(err).Errorln("can't read row")
			errCh <- err
			return
		}
		if !row.IsSimpleQuery() {
			log.Debugln("not query")
			output, err := row.Marshal()
			if err != nil {
				log.WithError(err).Errorln("Can't dump row")
				errCh <- err
				return

			}
			n, err := writer.Write(output)
			if !base.CheckReadWrite(n, len(output), err, errCh) {
				return
			}
			if err := writer.Flush(); err != nil {
				log.WithError(err).Errorln("can't flush writer")
				errCh <- err
				return
			}
			continue
		}
		query := string(row.descriptionBuf.Bytes()[:row.dataLength-1])
		log.WithField("query", query).Debugln("new query")
		if censorErr := acraCensor.HandleQuery(query); censorErr != nil {
			log.WithError(censorErr).Errorln("AcraCensor blocked query")
			// errCh <- censorErr
			errorMessage, err := NewPgError("AcraCensor blocked this query")
			if err != nil {
				log.WithError(err).Errorln("can't create postgresql error message")
				return
			}
			n, err := clientConnection.Write(errorMessage)
			if !base.CheckReadWrite(n, len(errorMessage), err, row.errCh) {
				return
			}
			n, err = clientConnection.Write(ReadyForQueryPacket)
			if !base.CheckReadWrite(n, len(ReadyForQueryPacket), err, row.errCh) {
				return
			}
			continue
		}

		output, err := row.Marshal()
		if err != nil {
			log.WithError(err).Errorln("Can't dump row")
			errCh <- err
			return

		}
		n, err := writer.Write(output)
		if !base.CheckReadWrite(n, len(output), err, errCh) {
			return
		}
		if err := writer.Flush(); err != nil {
			log.WithError(err).Errorln("can't flush writer")
			errCh <- err
			return
		}
	}
}

func (row *DataRow) IsSSLRequest() bool {
	return row.messageType[0] == 'S'
}

func (row *DataRow) IsSSLRequestDeny() bool {
	return row.messageType[0] == 'N'
}

func (proxy *PgProxy) PgDecryptStream(censor acracensor.AcraCensorInterface, decryptor base.Decryptor, tlsConfig *tls.Config, dbConnection net.Conn, clientConnection net.Conn, errCh chan<- error) {
	log.Debugln("pg db proxy")
	writer := bufio.NewWriter(clientConnection)

	reader := acra_io.NewExtendedBufferedReader(bufio.NewReader(dbConnection))
	row := DataRow{
		writeIndex:           0,
		output:               make([]byte, OUTPUT_DEFAULT_SIZE),
		columnDataBuf:        bytes.NewBuffer(make([]byte, COLUMN_DATA_DEFAULT_SIZE)),
		descriptionLengthBuf: make([]byte, 4),
		reader:               reader,
		writer:               writer,
	}
	firstByte := true
	for {
		if !row.readMessageType(reader, writer, errCh) {
			return
		}

		if firstByte {
			// https://www.postgresql.org/docs/9.1/static/protocol-flow.html#AEN92112
			// we should know that we shouldn't read anymore bytes
			firstByte = false
			if row.IsSSLRequestDeny() {
				log.Debugln("deny ssl request")
				writer.Flush()
				continue
			} else if row.IsSSLRequest() {
				if tlsConfig == nil {
					log.Errorln("To support TLS connections you must pass TLS key and certificate for AcraServer that will be used" +
						"for connections AcraServer->Database and CA certificate which will be used to verify certificate " +
						"from database")
					errCh <- network.ErrEmptyTLSConfig
					return
				}
				log.Debugln("Start tls proxy")
				// stop reading from client in goroutine
				if err := clientConnection.SetDeadline(time.Now()); err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
						Errorln("Can't set deadline")
					errCh <- err
					return
				}
				select {
				case <-proxy.TlsCh:
					break
				case <-time.NewTimer(TLS_TIMEOUT).C:
					log.Errorln("can't stop background goroutine to start tls handshake")
					proxy.errCh <- errors.New("can't stop background goroutine")
					return
				}
				log.Debugln("stop client connection")
				if err := clientConnection.SetDeadline(time.Time{}); err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantSetDeadlineToClientConnection).
						Errorln("Can't set deadline")
					errCh <- err
					return
				}
				log.Debugln("init tls with client")
				// convert to tls connection
				tlsClientConnection := tls.Server(clientConnection, tlsConfig)
				if err := writer.Flush(); err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Can't flush writer")
					errCh <- err
					return
				}
				if err := tlsClientConnection.Handshake(); err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Can't initialize tls connection with client")
					errCh <- err
					return
				}

				log.Debugln("Init tls with db")
				dbTLSConnection := tls.Client(dbConnection, tlsConfig)
				if err := dbTLSConnection.Handshake(); err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorDecryptorCantInitializeTLS).
						Errorln("Can't initialize tls connection with db")
					errCh <- err
					return
				}

				// restart proxing client's requests
				go proxy.PgProxyClientRequests(censor, dbTLSConnection, tlsClientConnection, errCh)
				reader = acra_io.NewExtendedBufferedReader(bufio.NewReader(dbTLSConnection))
				row.reader = reader
				writer = bufio.NewWriter(tlsClientConnection)
				row.writer = writer
				firstByte = true
				continue
			}
		}

		if !row.IsDataRow() {
			if !row.skipData(reader, writer, errCh) {
				return
			}
			writer.Flush()
			continue
		}

		log.Debugln("matched data row")

		row.writeIndex = 0

		if !row.ReadDataLength() {
			return
		}
		if !row.ReadColumnCount() {
			return
		}
		if row.columnCount == 0 {
			if !row.Flush() {
				return
			}
			break
		}
		log.Debugf("read column count: %v", row.columnCount)
		for i := 0; i < row.columnCount; i++ {
			// read column length
			row.CheckOutputSize(4)
			n, err := reader.Read(row.output[row.writeIndex : row.writeIndex+4])
			if !base.CheckReadWrite(n, 4, err, errCh) {
				return
			}
			// save pointer on column size
			row.columnSizePointer = row.output[row.writeIndex : row.writeIndex+4]
			row.writeIndex += 4
			columnDataLength := int(int32(binary.BigEndian.Uint32(row.columnSizePointer)))
			if columnDataLength == 0 || columnDataLength == -1 {
				log.Debugln("empty column")
				continue
			}
			if columnDataLength >= row.dataLength {
				log.Debugf("fake column length: column_data_length=%v, data_length=%v", columnDataLength, row.dataLength)
				if !row.Flush() {
					return
				}
				break
			}
			row.columnDataBuf.Reset()

			row.columnDataBuf.Grow(columnDataLength)
			row.CheckOutputSize(columnDataLength)
			// reassign column_size_p
			row.columnSizePointer = row.output[row.writeIndex-4 : row.writeIndex]

			// read column data
			n, err = reader.Read(row.output[row.writeIndex : row.writeIndex+columnDataLength])
			if !base.CheckReadWrite(n, columnDataLength, err, errCh) {
				return
			}
			// TODO check poison record before zone matching in two modes.
			// now zone matching executed every time
			// try to skip small piece of data that can't be valuable for us
			if (decryptor.IsWithZone() && columnDataLength >= zone.ZONE_ID_BLOCK_LENGTH) || columnDataLength >= base.KEY_BLOCK_LENGTH {
				decryptor.Reset()
				if decryptor.IsWholeMatch() {
					// poison record check
					// check only if has any action on detection
					if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
						log.Debugln("Check poison records")
						block, err := decryptor.SkipBeginInBlock(row.output[row.writeIndex : row.writeIndex+columnDataLength])
						if err == nil {
							poisoned, err := decryptor.CheckPoisonRecord(bytes.NewReader(block))
							if err != nil || poisoned {
								if poisoned {
									errCh <- base.ErrPoisonRecord
								} else {
									errCh <- err
								}
								return
							}
						}
					}
					// end poison record check

					decryptor.Reset()
					if !decryptor.IsWithZone() || decryptor.IsMatchedZone() {
						decrypted, err := decryptor.DecryptBlock(row.output[row.writeIndex : row.writeIndex+columnDataLength])
						if err == nil {
							copy(row.output[row.writeIndex:], decrypted)
							row.UpdateColumnAndDataSize(columnDataLength, len(decrypted))
							row.writeIndex += len(decrypted)
							continue
						} else if err == base.ErrPoisonRecord {
							log.Errorln(" poison record detected")
							errCh <- err
							return
						}
					} else {
						decryptor.MatchZoneBlock(row.output[row.writeIndex : row.writeIndex+columnDataLength])
					}
					row.writeIndex += columnDataLength
				} else {
					currentIndex := row.writeIndex
					endIndex := row.writeIndex + columnDataLength

					// check poison records
					if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
						log.Debugln("Check poison records")
						for {
							beginTagIndex, tagLength := decryptor.BeginTagIndex(row.output[currentIndex:endIndex])
							if beginTagIndex == utils.NOT_FOUND {
								log.Debugln("not found begin tag")
								break
							}
							log.Debugln("found begin tag")
							blockReader := bytes.NewReader(row.output[currentIndex+beginTagIndex+tagLength:])
							poisoned, err := decryptor.CheckPoisonRecord(blockReader)
							if err != nil || poisoned {
								if poisoned {
									errCh <- base.ErrPoisonRecord
								} else {
									errCh <- err
								}
								return
							}
							// try to find after founded tag with offset
							currentIndex += beginTagIndex + 1
						}
					}
					if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
						decryptor.MatchZoneInBlock(row.output[row.writeIndex : row.writeIndex+columnDataLength])
						row.writeIndex += columnDataLength
						continue
					}
					currentIndex = row.writeIndex
					halted := false
					for {
						beginTagIndex, tagLength := decryptor.BeginTagIndex(row.output[currentIndex:endIndex])
						if beginTagIndex == utils.NOT_FOUND {
							row.columnDataBuf.Write(row.output[currentIndex:endIndex])
							break
						}
						// convert to absolute index
						beginTagIndex += currentIndex
						row.columnDataBuf.Write(row.output[currentIndex:beginTagIndex])
						currentIndex = beginTagIndex

						key, err := decryptor.GetPrivateKey()
						if err != nil {
							log.Warningln("can't read private key")
							halted = true
							break
						}
						blockReader := bytes.NewReader(row.output[beginTagIndex+tagLength:])
						symKey, _, err := decryptor.ReadSymmetricKey(key, blockReader)
						if err != nil {
							log.Warningf("%v", utils.ErrorMessage("can't unwrap symmetric key", err))
							row.columnDataBuf.Write([]byte{row.output[currentIndex]})
							currentIndex++
							continue
						}
						data, err := decryptor.ReadData(symKey, decryptor.GetMatchedZoneId(), blockReader)
						if err != nil {
							log.Warningf("%v", utils.ErrorMessage("can't decrypt data with unwrapped symmetric key", err))
							row.columnDataBuf.Write([]byte{row.output[currentIndex]})
							currentIndex++
							continue
						}
						row.columnDataBuf.Write(data)
						currentIndex += tagLength + (len(row.output[beginTagIndex+tagLength:]) - blockReader.Len())
					}
					if !halted && row.columnDataBuf.Len() < columnDataLength {
						log.Debugln("decrypted")
						copy(row.output[row.writeIndex:], row.columnDataBuf.Bytes())
						row.writeIndex += row.columnDataBuf.Len()
						row.UpdateColumnAndDataSize(columnDataLength, row.columnDataBuf.Len())
						decryptor.ResetZoneMatch()
					} else {
						log.Debugln("not decrypted")
						row.writeIndex = endIndex
					}
				}
			} else {
				log.Debugln("skip decryption")
				row.writeIndex += columnDataLength
			}
		}
		log.Debugln("row flush")
		if !row.Flush() {
			return
		}
		decryptor.Reset()
		decryptor.ResetZoneMatch()
	}
}
