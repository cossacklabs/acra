package mysql

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cossacklabs/acra/decryptor/mysql/base"
)

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
