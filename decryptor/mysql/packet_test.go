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
