package common

import (
	"math"
	"strconv"
	"testing"
)

func TestValidateDefaultValue(t *testing.T) {
	type args struct {
		value    *string
		dataType EncryptedType
	}
	var (
		emptyString = ""
		int32String = strconv.FormatUint(math.MaxInt32, 10)
		int64String = strconv.FormatUint(math.MaxInt64, 10)
		// use max uint64 as value for int64 that should overflow
		invalidInt64String = strconv.FormatUint(math.MaxUint64, 10)
		// valid ASCII [0, 127]. All greater values validated as UTF8
		invalidString = string([]byte{128, 129})
		someString    = "some string"
	)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"nil value unknown", args{nil, EncryptedType_Unknown}, false},
		{"non-nil value unknown", args{&int32String, EncryptedType_Unknown}, true},
		{"invalid string", args{&invalidString, EncryptedType_String}, true},
		{"valid bytes", args{&invalidString, EncryptedType_Bytes}, false},
		{"empty string", args{&emptyString, EncryptedType_String}, false},
		{"empty bytes", args{&emptyString, EncryptedType_Bytes}, false},
		{"int32 string", args{&int32String, EncryptedType_Int32}, false},
		{"invalid integer int32 string", args{&int64String, EncryptedType_Int32}, true},
		{"invalid non-integer int32 string", args{&someString, EncryptedType_Int32}, true},
		{"int64 string", args{&int64String, EncryptedType_Int64}, false},
		{"invalid int64 string", args{&invalidInt64String, EncryptedType_Int64}, true},
		{"invalid non-integer int64 string", args{&someString, EncryptedType_Int64}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDefaultValue(tt.args.value, tt.args.dataType); (err != nil) != tt.wantErr {
				t.Errorf("ValidateDefaultValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
