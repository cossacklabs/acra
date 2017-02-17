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
	"encoding/binary"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	acra_io "github.com/cossacklabs/acra/io"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"io"
	"log"
	"os"
)

type DataRow struct {
	buf                    [1]byte
	output                 []byte
	description_length_buf []byte
	column_size_pointer    []byte
	column_data_buf        *bytes.Buffer
	write_index            int
	column_count           int
	data_length            int
	err_ch                 chan<- error
	reader                 *acra_io.ExtendedBufferedReader
	writer                 *bufio.Writer
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
	available_size := len(row.output[row.write_index:])
	if available_size < size {
		new_output := make([]byte, cap(row.output)+(size-available_size))
		copy(new_output, row.output)
		row.output = new_output
	}
}

func (row *DataRow) skipData(reader io.Reader, writer io.Writer, err_ch chan<- error) bool {
	n, err := reader.Read(row.description_length_buf)
	if !base.CheckReadWrite(n, 4, err, err_ch) {
		return false
	}
	n2, err := io.Copy(writer, bytes.NewReader(row.description_length_buf))
	if !base.CheckReadWrite(int(n2), 4, err, err_ch) {
		return false
	}

	description_length := int(binary.BigEndian.Uint32(row.description_length_buf)) - len(row.description_length_buf)
	n2, err = io.CopyN(writer, reader, int64(description_length))
	if !base.CheckReadWrite(int(n2), description_length, err, err_ch) {
		return false
	}
	return true
}

func (row *DataRow) readByte(reader io.Reader, writer io.Writer, err_ch chan<- error) bool {
	n, err := reader.Read(row.buf[:])
	if !base.CheckReadWrite(n, 1, err, err_ch) {
		return false
	}
	n, err = writer.Write(row.buf[:])
	if !base.CheckReadWrite(n, 1, err, err_ch) {
		return false
	}
	return true
}

func (row *DataRow) IsDataRow() bool {
	return row.buf[0] == DATA_ROW_MESSAGE_TYPE
}

func (row *DataRow) UpdateColumnAndDataSize(old_column_length, new_column_length int) bool {
	if old_column_length == new_column_length {
		return true
	}
	// something was decrypted and size should be less that was before
	log.Printf("Debug: modify response size: %v -> %v\n", old_column_length, new_column_length)

	// update column data size
	size_diff := old_column_length - new_column_length
	log.Printf("Debug: old column size: %v; New column size: %v\n", old_column_length, new_column_length)
	if new_column_length > old_column_length {
		row.err_ch <- errors.New("decrypted size is more than encrypted")
		return false
	}
	binary.BigEndian.PutUint32(row.column_size_pointer, uint32(new_column_length))
	log.Printf("Debug: old data size: %v; new data size: %v\n", row.data_length, row.data_length-size_diff)
	// update data row size
	row.data_length -= size_diff
	row.SetDataSize(row.data_length)
	return true
}

func (row *DataRow) ReadDataLength() bool {
	log.Println("Debug: read data length")
	// read full data row length
	n, err := row.reader.Read(row.output[:DATA_ROW_LENGTH_BUF_SIZE])
	if !base.CheckReadWrite(n, DATA_ROW_LENGTH_BUF_SIZE, err, row.err_ch) {
		return false
	}
	row.write_index += n
	row.data_length = int(binary.BigEndian.Uint32(row.output[:DATA_ROW_LENGTH_BUF_SIZE]))
	return true
}

func (row *DataRow) ReadColumnCount() bool {
	// read column count
	column_count_buf := row.output[DATA_ROW_LENGTH_BUF_SIZE : DATA_ROW_LENGTH_BUF_SIZE+2]
	n, err := row.reader.Read(column_count_buf)
	if !base.CheckReadWrite(n, 2, err, row.err_ch) {
		return false
	}
	row.write_index += 2
	row.column_count = int(binary.BigEndian.Uint16(column_count_buf))
	return true
}

func (row *DataRow) Flush() bool {
	n, err := row.writer.Write(row.output[:row.write_index])
	if !base.CheckReadWrite(n, row.write_index, err, row.err_ch) {
		return false
	}
	return true
}

func PgDecryptStream(decryptor base.Decryptor, rr *bufio.Reader, writer *bufio.Writer, err_ch chan<- error) {
	reader := acra_io.NewExtendedBufferedReader(rr)
	row := DataRow{
		write_index:            0,
		output:                 make([]byte, OUTPUT_DEFAULT_SIZE),
		column_data_buf:        bytes.NewBuffer(make([]byte, COLUMN_DATA_DEFAULT_SIZE)),
		description_length_buf: make([]byte, 4),
		reader:                 reader,
		writer:                 writer,
	}
	first_byte := true
	for {
		if !row.readByte(reader, writer, err_ch) {
			return
		}

		if first_byte {
			// https://www.postgresql.org/docs/9.1/static/protocol-flow.html#AEN92112
			// we should know that we shouldn't read anymore bytes
			first_byte = false
			if row.buf[0] == 'N' {
				writer.Flush()
				continue
			} else if row.buf[0] == 'S' {
				log.Println("Error: detected ssl connection. run postgresql without ssl or connect with sslmode=disable (PGSSLMODE=disable psql) and restart AcraServer. exiting")
				os.Exit(1)
			}
		}

		if !row.IsDataRow() {
			if !row.skipData(reader, writer, err_ch) {
				return
			}
			writer.Flush()
			continue
		}

		log.Println("Debug: matched data row")

		row.write_index = 0

		if !row.ReadDataLength() {
			return
		}
		if !row.ReadColumnCount() {
			return
		}
		if row.column_count == 0 {
			if !row.Flush() {
				return
			}
			break
		}
		log.Printf("Debug: read column count: %v\n", row.column_count)
		for i := 0; i < row.column_count; i++ {
			// read column length
			row.CheckOutputSize(4)
			n, err := reader.Read(row.output[row.write_index : row.write_index+4])
			if !base.CheckReadWrite(n, 4, err, err_ch) {
				return
			}
			// save pointer on column size
			row.column_size_pointer = row.output[row.write_index : row.write_index+4]
			row.write_index += 4
			column_data_length := int(int32(binary.BigEndian.Uint32(row.column_size_pointer)))
			if column_data_length == 0 || column_data_length == -1 {
				log.Println("Debug: empty column")
				continue
			}
			if column_data_length >= row.data_length {
				log.Printf("Debug: fake column length: column_data_length=%v, data_length=%v\n", column_data_length, row.data_length)
				if !row.Flush() {
					return
				}
				break
			}
			row.column_data_buf.Reset()

			row.column_data_buf.Grow(column_data_length)
			row.CheckOutputSize(column_data_length)
			// reassign column_size_p
			row.column_size_pointer = row.output[row.write_index-4 : row.write_index]

			// read column data
			n, err = reader.Read(row.output[row.write_index : row.write_index+column_data_length])
			if !base.CheckReadWrite(n, column_data_length, err, err_ch) {
				return
			}
			// TODO check poison record before zone matching in two modes.
			// now zone matching executed every time
			// try to skip small piece of data that can't be valuable for us
			if (decryptor.IsWithZone() && column_data_length >= zone.ZONE_ID_BLOCK_LENGTH) || column_data_length >= base.KEY_BLOCK_LENGTH {
				decryptor.Reset()
				if decryptor.IsWholeMatch() {
					// poison record check
					// check only if has any action on detection
					if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
						log.Println("Debug: check poison records")
						block, err := decryptor.SkipBeginInBlock(row.output[row.write_index : row.write_index+column_data_length])
						if err == nil {
							poisoned, err := decryptor.CheckPoisonRecord(bytes.NewReader(block))
							if err != nil || poisoned {
								if poisoned {
									err_ch <- base.ErrPoisonRecord
								} else {
									err_ch <- err
								}
								return
							}
						}
					}
					// end poison record check

					decryptor.Reset()
					if !decryptor.IsWithZone() || decryptor.IsMatchedZone() {
						decrypted, err := decryptor.DecryptBlock(row.output[row.write_index : row.write_index+column_data_length])
						if err == nil {
							copy(row.output[row.write_index:], decrypted)
							row.UpdateColumnAndDataSize(column_data_length, len(decrypted))
							row.write_index += len(decrypted)
							continue
						} else if err == base.ErrPoisonRecord {
							log.Println("Error: poison record detected")
							err_ch <- err
							return
						}
					} else {
						decryptor.MatchZoneBlock(row.output[row.write_index : row.write_index+column_data_length])
					}
					row.write_index += column_data_length
				} else {
					current_index := row.write_index
					end_index := row.write_index + column_data_length

					// check poison records
					if decryptor.GetPoisonCallbackStorage().HasCallbacks() {
						log.Println("Debug: check poison records")
						for {
							begin_tag_index, tag_length := decryptor.BeginTagIndex(row.output[current_index:end_index])
							if begin_tag_index == utils.NOT_FOUND {
								log.Println("Debug: not found begin tag")
								break
							}
							log.Println("Debug: found begin tag")
							block_reader := bytes.NewReader(row.output[current_index+begin_tag_index+tag_length:])
							poisoned, err := decryptor.CheckPoisonRecord(block_reader)
							if err != nil || poisoned {
								if poisoned {
									err_ch <- base.ErrPoisonRecord
								} else {
									err_ch <- err
								}
								return
							}
							// try to find after founded tag with offset
							current_index += begin_tag_index + 1
						}
					}
					if decryptor.IsWithZone() && !decryptor.IsMatchedZone() {
						decryptor.MatchZoneInBlock(row.output[row.write_index : row.write_index+column_data_length])
						row.write_index += column_data_length
						continue
					}
					current_index = row.write_index
					halted := false
					for {
						begin_tag_index, tag_length := decryptor.BeginTagIndex(row.output[current_index:end_index])
						if begin_tag_index == utils.NOT_FOUND {
							row.column_data_buf.Write(row.output[current_index:end_index])
							break
						}
						// convert to absolute index
						begin_tag_index += current_index
						row.column_data_buf.Write(row.output[current_index:begin_tag_index])
						current_index = begin_tag_index

						key, err := decryptor.GetPrivateKey()
						if err != nil {
							log.Println("Warning: can't read private key")
							halted = true
							break
						}
						block_reader := bytes.NewReader(row.output[begin_tag_index+tag_length:])
						sym_key, _, err := decryptor.ReadSymmetricKey(key, block_reader)
						if err != nil {
							row.column_data_buf.Write([]byte{row.output[current_index]})
							current_index++
							continue
						}
						data, err := decryptor.ReadData(sym_key, decryptor.GetMatchedZoneId(), block_reader)
						if err != nil {
							log.Printf("Warning: %v\n", utils.ErrorMessage("can't decrypt data with unwrapped symmetric key", err))
							row.column_data_buf.Write([]byte{row.output[current_index]})
							current_index++
							continue
						}
						row.column_data_buf.Write(data)
						current_index += tag_length + (len(row.output[begin_tag_index+tag_length:]) - block_reader.Len())
					}
					if !halted && row.column_data_buf.Len() < column_data_length {
						copy(row.output[row.write_index:], row.column_data_buf.Bytes())
						row.write_index += row.column_data_buf.Len()
						row.UpdateColumnAndDataSize(column_data_length, row.column_data_buf.Len())
						decryptor.ResetZoneMatch()
					} else {
						row.write_index = end_index
					}
				}
			} else {
				row.write_index += column_data_length
			}
		}
		if !row.Flush() {
			return
		}
		decryptor.Reset()
		decryptor.ResetZoneMatch()
	}
}
