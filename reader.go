package acra

import (
	"encoding/hex"
	"errors"
	"io"
	"strconv"
)

type DbReader interface {
	Read([]byte) (int, []byte, error)
}

var FAKE_DB_BYTE = errors.New("Fake db format byte")

type PgHexReader struct {
	buffer        []byte
	current_index int
	reader        io.Reader
}

func NewPgHexReader(reader io.Reader) *PgHexReader {
	return &PgHexReader{
		current_index: 0,
		reader:        reader,
		buffer:        make([]byte, KEY_BLOCK_LENGTH*2),
	}
}

func (reader *PgHexReader) Read(output []byte) (int, []byte, error) {
	// TODO check with big data block. should be checked size and readed to new buffer instead reader.buffer
	hex_data_length := len(output) * 2
	n, err := reader.reader.Read(reader.buffer[:hex_data_length])
	if err != nil {
		return n, reader.buffer[:n], err
	}
	if n != hex_data_length {
		return n, reader.buffer[:n], FAKE_ACRA_STRUCT
	}
	_, err = hex.Decode(output, reader.buffer[:n])
	return n, reader.buffer[:n], nil
}

func (reader *PgHexReader) returnData(err error) (int, []byte, error) {
	if reader.current_index != 0 {
		return reader.current_index, reader.buffer[:reader.current_index], err
	} else {
		return 0, nil, err
	}
}

type PgEscapeReader struct {
	buffer         []byte
	reader         io.Reader
	oct_char_buf   [3]byte
	oct_data_index byte
}

func NewPgEscapeReader(reader io.Reader) *PgEscapeReader {
	return &PgEscapeReader{
		buffer:         make([]byte, KEY_BLOCK_LENGTH*4),
		reader:         reader,
		oct_data_index: byte(0),
	}
}

func (reader *PgEscapeReader) returnData(err error) (int, []byte, error) {
	if reader.oct_data_index != 0 {
		return int(reader.oct_data_index), reader.buffer[:reader.oct_data_index], err
	} else {
		return 0, []byte{}, err
	}
}

func (reader *PgEscapeReader) reset() {
	reader.oct_data_index = 0
}

func (reader *PgEscapeReader) Read(output []byte) (int, []byte, error) {
	// TODO check with big data block. should be checked size and readed to new buffer instead reader.buffer
	data_index := 0
	oct_data_index := 0
	var char_buf [1]byte
	for {
		n, err := reader.reader.Read(char_buf[:])
		if err != nil {
			return oct_data_index, reader.buffer[:oct_data_index], err
		}
		if n != 1 {
			return oct_data_index, reader.buffer[:oct_data_index], FAKE_ACRA_STRUCT
		}
		reader.buffer[oct_data_index] = char_buf[0]
		oct_data_index++
		if !is_printable_octets(char_buf[0]) {
			return oct_data_index, reader.buffer[:oct_data_index], FAKE_ACRA_STRUCT
		}

		// if slash than next char must be slash too
		if char_buf[0] == SLASH_CHAR {
			// read next char
			_, err := reader.reader.Read(char_buf[:])
			if err != nil {
				return oct_data_index, reader.buffer[:oct_data_index], err
			}
			reader.buffer[oct_data_index] = char_buf[0]
			oct_data_index++
			if char_buf[0] == SLASH_CHAR {
				// just write slash char
				output[data_index] = char_buf[0]
				data_index++
			} else {
				reader.oct_char_buf[0] = char_buf[0]
				// read next 3 oct bytes
				n, err := io.ReadFull(reader.reader, reader.oct_char_buf[1:])
				if err != nil {
					return oct_data_index, reader.buffer[:oct_data_index], err
				}
				if n != len(reader.oct_char_buf)-1 {
					if n != 0 {
						copy(reader.buffer[oct_data_index:oct_data_index+n], reader.oct_char_buf[1:1+n])
						oct_data_index += n
					}
					return oct_data_index, reader.buffer[:oct_data_index], FAKE_ACRA_STRUCT
				}
				// parse 3 octal symbols
				num, err := strconv.ParseInt(string(reader.oct_char_buf[:]), 8, 9)
				if err != nil {
					return oct_data_index, reader.buffer[:oct_data_index], FAKE_ACRA_STRUCT
				}
				output[data_index] = byte(num)
				data_index++

				copy(reader.buffer[oct_data_index:oct_data_index+len(reader.oct_char_buf)-1], reader.oct_char_buf[1:])
				oct_data_index += 2
			}
		} else {
			// just write to data
			output[data_index] = char_buf[0]
			data_index++
		}
		if data_index == cap(output) {
			return len(output), reader.buffer[:oct_data_index], nil
		}
	}
}
