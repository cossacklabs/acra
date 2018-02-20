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
	"github.com/cossacklabs/acra/decryptor/base"
	acra_io "github.com/cossacklabs/acra/io"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

type DataRow struct {
	buf                  [1]byte
	output               []byte
	descriptionLengthBuf []byte
	columnSizePointer    []byte
	columnDataBuf        *bytes.Buffer
	writeIndex           int
	columnCount          int
	dataLength           int
	errCh                chan<- error
	reader               *acra_io.ExtendedBufferedReader
	writer               *bufio.Writer
}

const (
	DATA_ROW_LENGTH_BUF_SIZE = 4
	// random chosen
	OUTPUT_DEFAULT_SIZE      = 1024
	COLUMN_DATA_DEFAULT_SIZE = 1024
	// https://www.postgresql.org/docs/9.4/static/protocol-message-formats.html
	DATA_ROW_MESSAGE_TYPE byte = 'D'
)

/* override size in postgresql data row that starts with 4 byte of size */
func (row *DataRow) SetDataSize(size int) {
	binary.BigEndian.PutUint32(row.output[:DATA_ROW_LENGTH_BUF_SIZE], uint32(size))
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
	n, err := reader.Read(row.descriptionLengthBuf)
	if !base.CheckReadWrite(n, 4, err, errCh) {
		return false
	}
	n2, err := io.Copy(writer, bytes.NewReader(row.descriptionLengthBuf))
	if !base.CheckReadWrite(int(n2), 4, err, errCh) {
		return false
	}

	descriptionLength := int(binary.BigEndian.Uint32(row.descriptionLengthBuf)) - len(row.descriptionLengthBuf)
	n2, err = io.CopyN(writer, reader, int64(descriptionLength))
	if !base.CheckReadWrite(int(n2), descriptionLength, err, errCh) {
		return false
	}
	return true
}

func (row *DataRow) readByte(reader io.Reader, writer io.Writer, errCh chan<- error) bool {
	n, err := reader.Read(row.buf[:])
	if !base.CheckReadWrite(n, 1, err, errCh) {
		return false
	}
	n, err = writer.Write(row.buf[:])
	if !base.CheckReadWrite(n, 1, err, errCh) {
		return false
	}
	return true
}

func (row *DataRow) IsDataRow() bool {
	return row.buf[0] == DATA_ROW_MESSAGE_TYPE
}

func (row *DataRow) UpdateColumnAndDataSize(oldColumnLength, newColumnLength int) bool {
	if oldColumnLength == newColumnLength {
		return true
	}
	// something was decrypted and size should be less that was before
	log.Printf("Debug: modify response size: %v -> %v\n", oldColumnLength, newColumnLength)

	// update column data size
	sizeDiff := oldColumnLength - newColumnLength
	log.Printf("Debug: old column size: %v; New column size: %v\n", oldColumnLength, newColumnLength)
	if newColumnLength > oldColumnLength {
		row.errCh <- errors.New("decrypted size is more than encrypted")
		return false
	}
	binary.BigEndian.PutUint32(row.columnSizePointer, uint32(newColumnLength))
	log.Printf("Debug: old data size: %v; new data size: %v\n", row.dataLength, row.dataLength-sizeDiff)
	// update data row size
	row.dataLength -= sizeDiff
	row.SetDataSize(row.dataLength)
	return true
}

func (row *DataRow) ReadDataLength() bool {
	log.Println("Debug: read data length")
	// read full data row length
	n, err := row.reader.Read(row.output[:DATA_ROW_LENGTH_BUF_SIZE])
	if !base.CheckReadWrite(n, DATA_ROW_LENGTH_BUF_SIZE, err, row.errCh) {
		return false
	}
	row.writeIndex += n
	row.dataLength = int(binary.BigEndian.Uint32(row.output[:DATA_ROW_LENGTH_BUF_SIZE]))
	return true
}

func (row *DataRow) ReadColumnCount() bool {
	// read column count
	columnCountBuf := row.output[DATA_ROW_LENGTH_BUF_SIZE: DATA_ROW_LENGTH_BUF_SIZE+2]
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
	return true
}

func PgDecryptStream(decryptor base.Decryptor, dbConnection net.Conn, clientConnection net.Conn, errCh chan<- error) {
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
		if !row.readByte(reader, writer, errCh) {
			return
		}

		if firstByte {
			// https://www.postgresql.org/docs/9.1/static/protocol-flow.html#AEN92112
			// we should know that we shouldn't read anymore bytes
			firstByte = false
			if row.buf[0] == 'N' {
				writer.Flush()
				continue
			} else if row.buf[0] == 'S' {
				cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
				if err != nil {
					errCh <- err
					log.Println(err)
					return
				}
				// stop reading from client in goroutine
				if err = clientConnection.SetDeadline(time.Now()); err != nil{
					log.WithError(err).Error("can't set deadline")
					errCh <- err
					return
				}
				//
				time.Sleep(time.Millisecond)
				// reset deadline
				if err = clientConnection.SetDeadline(time.Time{}); err != nil{
					log.WithError(err).Error("can't set deadline")
					errCh <- err
					return
				}
				// convert to tls connection
				tlsClientConnection := tls.Server(clientConnection, &tls.Config{Certificates: []tls.Certificate{cer}})
				if err = writer.Flush(); err != nil {
					log.WithError(err).Error("can't flush writer")
					errCh <- err
					return
				}
				err = tlsClientConnection.Handshake()
				if err != nil {
					log.WithError(err).Error("can't initialize tls connection with client")
					errCh <- err
					return
				}

				dbTLSConnection := tls.Client(dbConnection, &tls.Config{InsecureSkipVerify: true})
				if err = dbTLSConnection.Handshake(); err != nil {
					log.WithError(err).Println("can't initialize tls connection with db")
					errCh <- err
					return
				}

				// restart proxing client's requests
				go network.Proxy(tlsClientConnection, dbTLSConnection, errCh)
				reader = acra_io.NewExtendedBufferedReader(bufio.NewReader(dbTLSConnection))
				row.reader = reader
				writer = bufio.NewWriter(tlsClientConnection)
				row.writer = writer
				firstByte = true
				continue
				//log.Println("Error: detected ssl connection. run postgresql without ssl or connect with sslmode=disable (PGSSLMODE=disable psql) and restart AcraServer. exiting")
				//os.Exit(1)
			}
		}

		if !row.IsDataRow() {
			if !row.skipData(reader, writer, errCh) {
				return
			}
			writer.Flush()
			continue
		}

		log.Println("Debug: matched data row")

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
		log.Printf("Debug: read column count: %v\n", row.columnCount)
		for i := 0; i < row.columnCount; i++ {
			// read column length
			row.CheckOutputSize(4)
			n, err := reader.Read(row.output[row.writeIndex: row.writeIndex+4])
			if !base.CheckReadWrite(n, 4, err, errCh) {
				return
			}
			// save pointer on column size
			row.columnSizePointer = row.output[row.writeIndex: row.writeIndex+4]
			row.writeIndex += 4
			columnDataLength := int(int32(binary.BigEndian.Uint32(row.columnSizePointer)))
			if columnDataLength == 0 || columnDataLength == -1 {
				log.Println("Debug: empty column")
				continue
			}
			if columnDataLength >= row.dataLength {
				log.Printf("Debug: fake column length: column_data_length=%v, data_length=%v\n", columnDataLength, row.dataLength)
				if !row.Flush() {
					return
				}
				break
			}
			row.columnDataBuf.Reset()

			row.columnDataBuf.Grow(columnDataLength)
			row.CheckOutputSize(columnDataLength)
			// reassign column_size_p
			row.columnSizePointer = row.output[row.writeIndex-4: row.writeIndex]

			// read column data
			n, err = reader.Read(row.output[row.writeIndex: row.writeIndex+columnDataLength])
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
						log.Println("Debug: check poison records")
						block, err := decryptor.SkipBeginInBlock(row.output[row.writeIndex: row.writeIndex+columnDataLength])
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
						decrypted, err := decryptor.DecryptBlock(row.output[row.writeIndex: row.writeIndex+columnDataLength])
						if err == nil {
							copy(row.output[row.writeIndex:], decrypted)
							row.UpdateColumnAndDataSize(columnDataLength, len(decrypted))
							row.writeIndex += len(decrypted)
							continue
						} else if err == base.ErrPoisonRecord {
							log.Println("Error: poison record detected")
							errCh <- err
							return
						}
					} else {
						decryptor.MatchZoneBlock(row.output[row.writeIndex: row.writeIndex+columnDataLength])
					}
					row.writeIndex += columnDataLength
				} else {
					currentIndex := row.writeIndex
					endIndex := row.writeIndex + columnDataLength

					// check poison records
					if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
						log.Println("Debug: check poison records")
						for {
							beginTagIndex, tagLength := decryptor.BeginTagIndex(row.output[currentIndex:endIndex])
							if beginTagIndex == utils.NOT_FOUND {
								log.Println("Debug: not found begin tag")
								break
							}
							log.Println("Debug: found begin tag")
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
						decryptor.MatchZoneInBlock(row.output[row.writeIndex: row.writeIndex+columnDataLength])
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
							log.Println("Warning: can't read private key")
							halted = true
							break
						}
						blockReader := bytes.NewReader(row.output[beginTagIndex+tagLength:])
						symKey, _, err := decryptor.ReadSymmetricKey(key, blockReader)
						if err != nil {
							log.Printf("Warning: %v\n", utils.ErrorMessage("can't unwrap symmetric key", err))
							row.columnDataBuf.Write([]byte{row.output[currentIndex]})
							currentIndex++
							continue
						}
						data, err := decryptor.ReadData(symKey, decryptor.GetMatchedZoneId(), blockReader)
						if err != nil {
							log.Printf("Warning: %v\n", utils.ErrorMessage("can't decrypt data with unwrapped symmetric key", err))
							row.columnDataBuf.Write([]byte{row.output[currentIndex]})
							currentIndex++
							continue
						}
						row.columnDataBuf.Write(data)
						currentIndex += tagLength + (len(row.output[beginTagIndex+tagLength:]) - blockReader.Len())
					}
					if !halted && row.columnDataBuf.Len() < columnDataLength {
						copy(row.output[row.writeIndex:], row.columnDataBuf.Bytes())
						row.writeIndex += row.columnDataBuf.Len()
						row.UpdateColumnAndDataSize(columnDataLength, row.columnDataBuf.Len())
						decryptor.ResetZoneMatch()
					} else {
						row.writeIndex = endIndex
					}
				}
			} else {
				row.writeIndex += columnDataLength
			}
		}
		if !row.Flush() {
			return
		}
		decryptor.Reset()
		decryptor.ResetZoneMatch()
	}
}
