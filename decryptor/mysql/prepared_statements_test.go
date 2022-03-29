package mysql

import (
	"reflect"
	"testing"

	"github.com/cossacklabs/acra/decryptor/base"
)

func TestNewMysqlCopyTextBoundValue(t *testing.T) {
	t.Run("textData not equals - success", func(t *testing.T) {
		sourceData := []byte("test-data")
		boundValue := NewMysqlCopyTextBoundValue(sourceData, base.BinaryFormat, TypeBlob)

		sourceData[0] = 22

		value, err := boundValue.GetData(nil)
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(sourceData, value) {
			t.Fatal("BoundValue data should not be equal to sourceData")
		}
	})

	t.Run("nil data provided", func(t *testing.T) {
		boundValue := NewMysqlCopyTextBoundValue(nil, base.BinaryFormat, TypeBlob)
		value, err := boundValue.GetData(nil)
		if err != nil {
			t.Fatal(err)
		}
		// we need to validate that textData is nil if nil was provided - required for handling NULL values
		if value != nil {
			t.Fatal("BoundValue data should be nil")
		}
	})
}
