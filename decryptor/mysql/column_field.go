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

package mysql

import (
	"encoding/binary"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
)

// ColumnDescription https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
type ColumnDescription struct {
	changed bool
	// field as byte slice
	data         []byte
	Schema       []byte
	Table        []byte
	OrgTable     []byte
	Name         []byte
	OrgName      []byte
	Charset      uint16
	ColumnLength uint32
	Type         uint8
	Flag         uint16
	Decimal      uint8

	DefaultValueLength uint64
	DefaultValue       []byte
}

// ParseResultField parses binary field and returns ColumnDescription
func ParseResultField(data []byte) (*ColumnDescription, error) {
	field := &ColumnDescription{}
	field.data = data

	var n int
	var err error
	//skip catalog, always def
	pos := 0
	n, err = SkipLengthEncodedString(data)
	if err != nil {

		return nil, err
	}
	pos += n

	//schema
	field.Schema, n, err = LengthEncodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//table
	field.Table, n, err = LengthEncodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//org_table
	field.OrgTable, n, err = LengthEncodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//name
	field.Name, n, err = LengthEncodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//org_name
	field.OrgName, n, err = LengthEncodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//skip 0x0C constant field
	pos++

	//charset
	field.Charset = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	//column length
	field.ColumnLength = binary.LittleEndian.Uint32(data[pos:])
	pos += 4

	//type
	field.Type = data[pos]
	pos++

	//flag
	field.Flag = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	//decimals 1
	field.Decimal = data[pos]
	pos++

	//filter [0x00][0x00]
	pos += 2

	field.DefaultValue = nil
	//if more data, command was field list
	if len(data) > pos {
		//length of default value lenenc-int
		field.DefaultValueLength, _, n, err = LengthEncodedInt(data[pos:])
		if err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Errorln("Can't get length encoded integer of default value length")
			return nil, err
		}
		pos += n

		if pos+int(field.DefaultValueLength) > len(data) {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).Errorln("Incorrect position, malformed packet")
			err = ErrMalformPacket
			return nil, err
		}

		//default value string[$len]
		field.DefaultValue = data[pos:(pos + int(field.DefaultValueLength))]
	}
	return field, nil
}

// IsBinary true if field type is binary
func (field *ColumnDescription) IsBinary() bool {
	return IsBinaryColumn(field.Type)
}

// Dump https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
func (field *ColumnDescription) Dump() []byte {
	if field.data != nil && !field.changed {
		return field.data
	}
	// column description has 7 length encoded strings. each string have 1-4 bytes with their length
	// catalog field always has value "def" and 1 byte for length
	// one field is constant 0x0C and has 1 byte for length
	// left 5 fields may have 8 byte (64bit) for length per field
	// (5 * 8) + 4 ("def" + 1 byte for length ) + 1 (0x0C) = 45
	// each of 7 length encoded string fields may have 8 byte (max) for encoded length at start.
	// https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
	l := len(field.Schema) + len(field.Table) + len(field.OrgTable) + len(field.Name) + len(field.OrgName) + len(field.DefaultValue) + 45

	data := make([]byte, 0, l)

	data = append(data, PutLengthEncodedString([]byte("def"))...)

	data = append(data, PutLengthEncodedString(field.Schema)...)

	data = append(data, PutLengthEncodedString(field.Table)...)
	data = append(data, PutLengthEncodedString(field.OrgTable)...)

	data = append(data, PutLengthEncodedString(field.Name)...)
	data = append(data, PutLengthEncodedString(field.OrgName)...)

	// length of fixed-length fields
	// https://dev.mysql.com/doc/internals/en/com-query-response.html#column-definition
	data = append(data, 0x0c)

	data = append(data, Uint16ToBytes(field.Charset)...)
	data = append(data, Uint32ToBytes(field.ColumnLength)...)
	data = append(data, field.Type)
	data = append(data, Uint16ToBytes(field.Flag)...)
	data = append(data, field.Decimal)
	// filler
	data = append(data, 0, 0)

	if field.DefaultValue != nil {
		data = append(data, Uint64ToBytes(field.DefaultValueLength)...)
		data = append(data, field.DefaultValue...)
	}

	return data
}
