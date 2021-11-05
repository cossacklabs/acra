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

		if reflect.DeepEqual(sourceData, boundValue.GetData(nil)) {
			t.Fatal("BoundValue data should not be equal to sourceData")
		}
	})

	t.Run("nil data provided", func(t *testing.T) {
		boundValue := NewMysqlCopyTextBoundValue(nil, base.BinaryFormat, TypeBlob)

		// we need to validate that textData is nil if nil was provided - required for handling NULL values
		if boundValue.GetData(nil) != nil {
			t.Fatal("BoundValue data should be nil")
		}
	})
}
