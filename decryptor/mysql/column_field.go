package mysql

import "encoding/binary"

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

func ParseResultField(data []byte) (*ColumnDescription, error) {
	field := &ColumnDescription{}
	field.data = data

	var n int
	var err error
	//skip catalog, always def
	pos := 0
	n, err = SkipLengthEnodedString(data)
	if err != nil {
		return nil, err
	}
	pos += n

	//schema
	field.Schema, _, n, err = LengthEnodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//table
	field.Table, _, n, err = LengthEnodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//org_table
	field.OrgTable, _, n, err = LengthEnodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//name
	field.Name, _, n, err = LengthEnodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//org_name
	field.OrgName, _, n, err = LengthEnodedString(data[pos:])
	if err != nil {
		return nil, err
	}
	pos += n

	//skip oc
	pos += 1

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
		field.DefaultValueLength, _, n = LengthEncodedInt(data[pos:])
		pos += n

		if pos+int(field.DefaultValueLength) > len(data) {
			err = ErrMalformPacket
			return nil, err
		}

		//default value string[$len]
		field.DefaultValue = data[pos:(pos + int(field.DefaultValueLength))]
	}
	return field, nil
}

func (field *ColumnDescription) IsBinary() bool {
	return IsBinaryColumn(int(field.Type))
}

func (field *ColumnDescription) Dump() []byte {
	if field.data != nil && !field.changed {
		return field.data
	}

	l := len(field.Schema) + len(field.Table) + len(field.OrgTable) + len(field.Name) + len(field.OrgName) + len(field.DefaultValue) + 48

	data := make([]byte, 0, l)

	data = append(data, PutLengthEncodedString([]byte("def"))...)

	data = append(data, PutLengthEncodedString(field.Schema)...)

	data = append(data, PutLengthEncodedString(field.Table)...)
	data = append(data, PutLengthEncodedString(field.OrgTable)...)

	data = append(data, PutLengthEncodedString(field.Name)...)
	data = append(data, PutLengthEncodedString(field.OrgName)...)

	// length of fixed-length fields
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
