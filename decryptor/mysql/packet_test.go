package mysql

import (
	"testing"

	"github.com/stretchr/testify/assert"

	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
)

func TestGetBindParameters(t *testing.T) {
	t.Run("parse StatementExecute with nil value", func(t *testing.T) {
		rawData := []byte{23, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 8, 0}
		packet := Packet{
			data: rawData,
		}

		expectedParams := 1
		boundValues, err := packet.GetBindParameters(expectedParams)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, len(boundValues), expectedParams)
		assert.Equal(t, boundValues[0].GetType(), uint8(base_mysql.TypeLongLong))
		data, _ := boundValues[0].GetData(nil)
		assert.Equal(t, []byte(nil), data)
	})

	t.Run("parse StatementExecute with several nil values", func(t *testing.T) {
		rawData := []byte{23, 1, 0, 0, 0, 0, 1, 0, 0, 0, 253, 1, 1, 8, 0, 8, 0, 8, 0, 8, 0, 8, 0, 8, 0, 8, 0, 8, 0, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0}
		packet := Packet{
			data: rawData,
		}

		expectedParams := 9
		boundValues, err := packet.GetBindParameters(expectedParams)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, len(boundValues), expectedParams)

		for _, value := range boundValues {
			assert.Equal(t, value.GetType(), uint8(base_mysql.TypeLongLong))
		}

		data, _ := boundValues[1].GetData(nil)
		assert.Equal(t, []byte{0x31}, data)

		for i := 2; i < len(boundValues); i++ {
			data, _ = boundValues[1].GetData(nil)
			assert.Equal(t, []byte{0x31}, data)
		}
	})

	t.Run("parse StatementExecute nil and data values", func(t *testing.T) {
		rawData := []byte{23, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 8, 0, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0}
		packet := Packet{
			data: rawData,
		}

		expectedParams := 2
		boundValues, err := packet.GetBindParameters(expectedParams)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, len(boundValues), expectedParams)

		for _, value := range boundValues {
			assert.Equal(t, value.GetType(), uint8(base_mysql.TypeLongLong))
		}

		data, _ := boundValues[0].GetData(nil)
		assert.Equal(t, []byte(nil), data)

		data, _ = boundValues[1].GetData(nil)
		assert.Equal(t, []byte{0x31}, data)
	})
}

func TestParseResultField(t *testing.T) {
	t.Run("_MariaDB: parse field with Point extended metadata", func(t *testing.T) {
		rawData := []byte{3, 100, 101, 102, 4, 116, 101, 115, 116, 8, 99, 117, 115, 116, 111, 109, 101, 114, 8, 99, 117, 115, 116, 111, 109, 101, 114, 6, 115, 104, 97, 112, 101, 98, 6, 115, 104, 97, 112, 101, 98, 7, 0, 5, 112, 111, 105, 110, 116, 12, 63, 0, 255, 255, 255, 255, 255, 144, 0, 0, 0, 0}
		packet := Packet{
			data: rawData,
		}

		columnDescription, err := ParseResultField(&packet, true)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, []byte("shapeb"), columnDescription.Name)
		assert.Equal(t, []byte("customer"), columnDescription.OrgTable)
		assert.Equal(t, []byte("customer"), columnDescription.Table)
		assert.Equal(t, []byte("shapeb"), columnDescription.OrgName)
		assert.Equal(t, []byte("test"), columnDescription.Schema)
		assert.Equal(t, uint16(63), columnDescription.Charset)
		assert.Equal(t, base.TypeGeometry, columnDescription.Type)
		assert.True(t, len(columnDescription.ExtendedTypeInfo) > 0)
		assert.True(t, bytes.Contains(columnDescription.ExtendedTypeInfo, []byte("point")))

		// check serialization
		assert.Equal(t, packet.Dump(), packet.data)
	})

	t.Run("_MariaDB: parse field with Multipolygon extended metadata", func(t *testing.T) {
		rawData := []byte{3, 100, 101, 102, 4, 116, 101, 115, 116, 8, 99, 117, 115, 116, 111, 109, 101, 114, 8, 99, 117, 115, 116, 111, 109, 101, 114, 6, 115, 104, 97, 112, 101, 98, 6, 115, 104, 97, 112, 101, 98, 14, 0, 12, 109, 117, 108, 116, 105, 112, 111, 108, 121, 103, 111, 110, 12, 63, 0, 255, 255, 255, 255, 255, 144, 0, 0, 0, 0}
		packet := Packet{
			data: rawData,
		}

		columnDescription, err := ParseResultField(&packet, true)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, []byte("shapeb"), columnDescription.Name)
		assert.Equal(t, []byte("customer"), columnDescription.OrgTable)
		assert.Equal(t, []byte("customer"), columnDescription.Table)
		assert.Equal(t, []byte("shapeb"), columnDescription.OrgName)
		assert.Equal(t, []byte("test"), columnDescription.Schema)
		assert.Equal(t, uint16(63), columnDescription.Charset)
		assert.Equal(t, base.TypeGeometry, columnDescription.Type)
		assert.True(t, len(columnDescription.ExtendedTypeInfo) > 0)
		assert.True(t, bytes.Contains(columnDescription.ExtendedTypeInfo, []byte("multipolygon")))

		// check serialization
		assert.Equal(t, packet.Dump(), packet.data)
	})

	t.Run("_MariaDB: parse field without extended metadata", func(t *testing.T) {
		rawData := []byte{3, 100, 101, 102, 4, 116, 101, 115, 116, 8, 99, 117, 115, 116, 111, 109, 101, 114, 8, 99, 117, 115, 116, 111, 109, 101, 114, 5, 101, 109, 97, 105, 108, 5, 101, 109, 97, 105, 108, 0, 12, 63, 0, 255, 255, 255, 255, 252, 144, 0, 0, 0, 0}
		packet := Packet{
			data: rawData,
		}

		columnDescription, err := ParseResultField(&packet, true)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, []byte("email"), columnDescription.Name)
		assert.Equal(t, []byte("customer"), columnDescription.OrgTable)
		assert.Equal(t, []byte("customer"), columnDescription.Table)
		assert.Equal(t, []byte("email"), columnDescription.OrgName)
		assert.Equal(t, []byte("test"), columnDescription.Schema)
		assert.Equal(t, uint16(63), columnDescription.Charset)
		assert.Equal(t, base.TypeBlob, columnDescription.Type)
		assert.True(t, len(columnDescription.ExtendedTypeInfo) == 0)

		// check serialization
		assert.Equal(t, packet.Dump(), packet.data)
	})

	t.Run("_MySQL: parse default field", func(t *testing.T) {
		rawData := []byte{3, 100, 101, 102, 4, 116, 101, 115, 116, 8, 99, 117, 115, 116, 111, 109, 101, 114, 8, 99, 117, 115, 116, 111, 109, 101, 114, 4, 110, 97, 109, 101, 4, 110, 97, 109, 101, 12, 8, 0, 255, 0, 0, 0, 253, 0, 0, 0, 0, 0}
		packet := Packet{
			data: rawData,
		}

		columnDescription, err := ParseResultField(&packet, false)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, []byte("name"), columnDescription.Name)
		assert.Equal(t, []byte("customer"), columnDescription.OrgTable)
		assert.Equal(t, []byte("customer"), columnDescription.Table)
		assert.Equal(t, []byte("name"), columnDescription.OrgName)
		assert.Equal(t, []byte("test"), columnDescription.Schema)
		assert.Equal(t, uint16(8), columnDescription.Charset)
		assert.Equal(t, base.TypeVarString, columnDescription.Type)
		assert.True(t, len(columnDescription.ExtendedTypeInfo) == 0)

		// check serialization
		assert.Equal(t, packet.Dump(), packet.data)
	})
}
