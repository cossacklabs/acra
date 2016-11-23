package postgresql

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	acra_io "github.com/cossacklabs/acra/io"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/acra/decryptor/base"
)

type DataRow struct {
	buf                    [1]byte
	output                 []byte
	description_length_buf []byte
	column_data_buf        *bytes.Buffer
	write_index            int
}

const (
	DATA_ROW_LENGTH_BUF_SIZE = 4
	// random choosen
	OUTPUT_DEFAULT_SIZE      = 1024
	COLUMN_DATA_DEFAULT_SIZE = 1024
	// https://www.postgresql.org/docs/9.4/static/protocol-message-formats.html
	PARSE_MESSAGE_TYPE            byte = '1'
	BIND_MESSAGE_TYPE             byte = '2'
	DATA_DESCRIPTION_MESSAGE_TYPE byte = 'T'
	DATA_ROW_MESSAGE_TYPE         byte = 'D'
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
	log.Printf("Debug: skip data length (bind or data description): %v\n", description_length)
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

func (row *DataRow) SkipDataDescription(reader *acra_io.ExtendedBufferedReader, writer *bufio.Writer, err_ch chan<- error) bool {
	/* Detect data description packet from postgresql that should start with T and
	4 byte length of description, proxy data as is and return when should be started data row packets*/
	packet_begin := true
	for {
		if reader.Buffered() == 0 {
			writer.Flush()
			packet_begin = true
		}

		if !row.readByte(reader, writer, err_ch) {
			return false
		}
		if packet_begin {
			if row.buf[0] == PARSE_MESSAGE_TYPE {
				log.Println("Debug: skip parse block")
				if !row.skipData(reader, writer, err_ch) {
					return false
				}
				if !row.readByte(reader, writer, err_ch) {
					return false
				}
			}
			if row.buf[0] == BIND_MESSAGE_TYPE {
				log.Println("Debug: skip bind block")
				if !row.skipData(reader, writer, err_ch) {
					return false
				}
				if !row.readByte(reader, writer, err_ch) {
					return false
				}
			}
			if row.buf[0] == DATA_DESCRIPTION_MESSAGE_TYPE {
				log.Println("Debug: skip data description block")
				if !row.skipData(reader, writer, err_ch) {
					return false
				}
				if !row.readByte(reader, writer, err_ch) {
					return false
				}
			}
			if row.buf[0] == DATA_ROW_MESSAGE_TYPE {
				log.Println("Debug: matched data row")
				return true
			}
			packet_begin = false
		}
	}
}

func PgDecryptStream(decryptor base.Decryptor, rr *bufio.Reader, writer *bufio.Writer, err_ch chan<- error) {
	r := DataRow{
		write_index:            0,
		output:                 make([]byte, OUTPUT_DEFAULT_SIZE),
		column_data_buf:        bytes.NewBuffer(make([]byte, COLUMN_DATA_DEFAULT_SIZE)),
		description_length_buf: make([]byte, 4),
	}
	var buf_reader = bufio.NewReader(&bytes.Reader{})
	var buf_writer = bufio.NewWriter(r.column_data_buf)
	reader := acra_io.NewExtendedBufferedReader(rr)
	inner_err_ch := make(chan error, 1)
	for {
		if !r.SkipDataDescription(reader, writer, err_ch) {
			return
		}
		log.Println("Debug: skiped row description")

		r.write_index = 0

		log.Println("Debug: read data length")
		// read full data row length
		n, err := reader.Read(r.output[:DATA_ROW_LENGTH_BUF_SIZE])
		if !base.CheckReadWrite(n, DATA_ROW_LENGTH_BUF_SIZE, err, err_ch) {
			return
		}
		r.write_index += n
		data_length := int(binary.BigEndian.Uint32(r.output[:DATA_ROW_LENGTH_BUF_SIZE]))
		// read column count
		column_count_buf := r.output[DATA_ROW_LENGTH_BUF_SIZE : DATA_ROW_LENGTH_BUF_SIZE+2]
		n, err = reader.Read(column_count_buf)
		if !base.CheckReadWrite(n, 2, err, err_ch) {
			return
		}
		r.write_index += 2
		field_count := int(binary.BigEndian.Uint16(column_count_buf))
		if field_count == 0 {
			log.Printf("Debug: fake column count: %v\n", field_count)
			n, err := writer.Write(r.output[:r.write_index])
			if !base.CheckReadWrite(n, r.write_index, err, err_ch) {
				return
			}
			break
		}
		log.Printf("Debug: read column count: %v\n", field_count)
		for i := 0; i < field_count; i++ {
			// read column length
			log.Printf("Debug: read %v column length\n", i)
			r.CheckOutputSize(4)
			n, err = reader.Read(r.output[r.write_index : r.write_index+4])
			if !base.CheckReadWrite(n, 4, err, err_ch) {
				return
			}
			// save pointer on column size
			column_size_p := r.output[r.write_index : r.write_index+4]
			r.write_index += 4
			column_data_length := int(int32(binary.BigEndian.Uint32(column_size_p)))
			log.Printf("Debug: column[%v] length: %v\n", i, column_data_length)
			if column_data_length == 0 || column_data_length == -1 {
				log.Println("Debug: empty column")
				continue
			}
			if column_data_length >= data_length {
				log.Printf("Debug: fake column length: column_data_length=%v, data_length=%v\n", column_data_length, data_length)
				n, err := writer.Write(r.output[:r.write_index])
				if !base.CheckReadWrite(n, n, err, err_ch) {
					return
				}
				break
			}
			r.column_data_buf.Reset()
			if r.column_data_buf.Cap() < column_data_length {
				log.Printf("Debug: increase column_data_buf size from %v\n", r.column_data_buf.Cap())
				r.column_data_buf.Grow(column_data_length - r.column_data_buf.Cap())
			}

			r.CheckOutputSize(column_data_length)
			// reassign column_size_p
			column_size_p = r.output[r.write_index-4 : r.write_index]

			// read column data
			log.Printf("Debug: read %v column data[%v]\n", i, column_data_length)
			n, err = reader.Read(r.output[r.write_index : r.write_index+column_data_length])
			if !base.CheckReadWrite(n, column_data_length, err, err_ch) {
				return
			}
			// try to skip small piece of data that can't be valuable for us
			if (decryptor.IsWithZone() && column_data_length >= zone.ZONE_ID_BLOCK_LENGTH) || column_data_length >= base.KEY_BLOCK_LENGTH {
				// point reader on new data block
				buf_reader.Reset(bytes.NewReader(r.output[r.write_index : r.write_index+column_data_length]))
				decryptor.Reset()
				// parse acrastruct
				base.DecryptStream(decryptor, buf_reader, buf_writer, inner_err_ch)

				err = <-inner_err_ch
				log.Printf("Debug: decryption finished with err=%v\n", err)
				if err != io.EOF {
					err_ch <- err
					return
				}
				_, err = buf_writer.Write(decryptor.GetMatched())
				if !base.CheckReadWrite(1, 1, err, err_ch) {
					return
				}
				decryptor.Reset()
				buf_writer.Flush()

				if r.column_data_buf.Len() < column_data_length {
					// something was decrypted and size should be less that was before
					log.Printf("Debug: modify response size: %v -> %v\n", column_data_length, r.column_data_buf.Len())
					// update column data size
					size_diff := column_data_length - r.column_data_buf.Len()
					new_column_size := column_data_length - size_diff
					log.Printf("Debug: old column size: %v; New column size: %v\n", column_data_length, new_column_size)
					if r.column_data_buf.Len() > column_data_length {
						err_ch <- errors.New("decrypted size is more than encrypted")
						return
					}
					binary.BigEndian.PutUint32(column_size_p, uint32(new_column_size))
					log.Printf("Debug: old data size: %v; new data size: %v\n", data_length, data_length-size_diff)
					// update data row size
					data_length -= size_diff
					r.SetDataSize(data_length)
					// cope encrypted data instead raw data
					copy(r.output[r.write_index:], r.column_data_buf.Bytes())
				}
				r.write_index += r.column_data_buf.Len()
			} else {
				r.write_index += column_data_length
			}
		}
		//Read data length
		n, err = writer.Write(r.output[:r.write_index])
		if !base.CheckReadWrite(n, r.write_index, err, err_ch) {
			return
		}
		decryptor.Reset()
		decryptor.ResetZoneMatch()
	}
}
