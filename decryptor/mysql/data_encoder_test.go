package mysql

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/base/config/common"
)

const binaryFormat = true
const textFormat = false

func TestSuccessfulTextEncoding(t *testing.T) {
	type testcase struct {
		input    []byte
		dataType common.EncryptedType
		expected []byte
	}

	testcases := []testcase{
		{[]byte("string"), common.EncryptedType_String, []byte("\x06string")},
		{[]byte("bytes"), common.EncryptedType_Bytes, []byte("\x05bytes")},
		{[]byte("3200"), common.EncryptedType_Int32, []byte("\x043200")},
		{[]byte("64000000"), common.EncryptedType_Int64, []byte("\b64000000")},
	}

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", textFormat, -1, 0, 0)
		// mark context as decrypted
		ctx := base.MarkDecryptedContext(context.Background())

		dataType, err := testcase.dataType.ToConfigString()
		if err != nil {
			t.Fatal(err)
		}
		setting := &config.BasicColumnEncryptionSetting{
			DataType: dataType,
		}
		logger := logrus.NewEntry(logrus.New())

		_, encoded, err := encoder.encodeText(ctx, testcase.input, setting, info, logger)

		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(encoded, testcase.expected) {
			t.Fatalf("incorrect encoding: %q but expected %q\n", encoded, testcase.expected)
		}
	}
}

func TestSuccessfulBinaryEncoding(t *testing.T) {
	type testcase struct {
		input      []byte
		dataTypeID uint32
		expected   []byte
	}

	testcases := []testcase{
		{[]byte("string"), uint32(base_mysql.TypeString), []byte("\x06string")},
		{[]byte("bytes"), uint32(base_mysql.TypeBlob), []byte("\x05bytes")},
		{[]byte("3200"), uint32(base_mysql.TypeLong), []byte("\x80\f\x00\x00")},
		{[]byte("64000000"), uint32(base_mysql.TypeLongLong), []byte("\x00\x90\xd0\x03\x00\x00\x00\x00")},
	}

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", binaryFormat, -1, 0, 0)
		// mark context as decrypted
		ctx := base.MarkDecryptedContext(context.Background())

		setting := &config.BasicColumnEncryptionSetting{
			DataTypeID: testcase.dataTypeID,
		}
		logger := logrus.NewEntry(logrus.New())

		_, encoded, err := encoder.encodeBinary(ctx, testcase.input, setting, info, logger)

		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(encoded, testcase.expected) {
			t.Fatalf("incorrect encoding: %q but expected %q\n", encoded, testcase.expected)
		}
	}
}

func TestFailingTextEncodingWithDefault(t *testing.T) {
	type testcase struct {
		input        []byte
		dataTypeID   uint32
		defaultValue string
		expected     []byte
	}

	testcases := []testcase{
		{[]byte("string"), uint32(base_mysql.TypeString), "default_string", []byte("\x0edefault_string")},
		{[]byte("bytes"), uint32(base_mysql.TypeBlob), "ZGVmYXVsdF9ieXRlcw==", []byte("\rdefault_bytes")},
		{[]byte("invalid_int32"), uint32(base_mysql.TypeLong), "25519", []byte("\x0525519")},
		{[]byte("invalid_int64"), uint32(base_mysql.TypeLongLong), "448", []byte("\x03448")},
	}

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", textFormat, -1, 0, 0)
		ctx := context.Background()
		setting := &config.BasicColumnEncryptionSetting{
			DataTypeID:       testcase.dataTypeID,
			ResponseOnFail:   common.ResponseOnFailDefault,
			DefaultDataValue: &testcase.defaultValue,
		}
		logger := logrus.NewEntry(logrus.New())

		_, encoded, err := encoder.encodeText(ctx, testcase.input, setting, info, logger)

		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(encoded, testcase.expected) {
			t.Fatalf("incorrect encoding: %q but expected %q\n", encoded, testcase.expected)
		}
	}
}

func TestFailingBinaryEncodingWithDefault(t *testing.T) {
	type testcase struct {
		input        []byte
		dataTypeID   uint32
		defaultValue string
		expected     []byte
	}

	testcases := []testcase{
		{[]byte("string"), uint32(base_mysql.TypeString), "default_string", []byte("\x0edefault_string")},
		{[]byte("bytes"), uint32(base_mysql.TypeBlob), "ZGVmYXVsdF9ieXRlcw==", []byte("\rdefault_bytes")},
		{[]byte("invalid_int32"), uint32(base_mysql.TypeLong), "25519", []byte("\xafc\x00\x00")},
		{[]byte("invalid_int64"), uint32(base_mysql.TypeLongLong), "448", []byte("\xc0\x01\x00\x00\x00\x00\x00\x00")},
	}

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", binaryFormat, -1, 0, 0)
		ctx := context.Background()
		setting := &config.BasicColumnEncryptionSetting{
			DataTypeID:       testcase.dataTypeID,
			ResponseOnFail:   common.ResponseOnFailDefault,
			DefaultDataValue: &testcase.defaultValue,
		}
		logger := logrus.NewEntry(logrus.New())

		_, encoded, err := encoder.encodeBinary(ctx, testcase.input, setting, info, logger)

		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(encoded, testcase.expected) {
			t.Fatalf("incorrect encoding: %q but expected %q\n", encoded, testcase.expected)
		}
	}
}

func TestFailingTextEncodingWithEncodingError(t *testing.T) {
	type testcase struct {
		input      []byte
		dataTypeID uint32
	}

	testcases := []testcase{
		{[]byte("string"), uint32(base_mysql.TypeString)},
		{[]byte("bytes"), uint32(base_mysql.TypeBlob)},
		{[]byte("invalid_int32"), uint32(base_mysql.TypeLong)},
		{[]byte("invalid_int64"), uint32(base_mysql.TypeLongLong)},
	}

	column := "cossack_column"
	expectedError := base.NewEncodingError(column)

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", textFormat, -1, 0, 0)
		ctx := context.Background()
		setting := &config.BasicColumnEncryptionSetting{
			Name:           column,
			DataTypeID:     testcase.dataTypeID,
			ResponseOnFail: common.ResponseOnFailError,
		}
		logger := logrus.NewEntry(logrus.New())

		_, _, err := encoder.encodeText(ctx, testcase.input, setting, info, logger)

		if !errors.Is(err, expectedError) {
			t.Fatalf("expected error %q, but found %q", expectedError, err)
		}
	}
}

func TestFailingBinaryEncodingWithEncodingError(t *testing.T) {
	type testcase struct {
		input      []byte
		dataTypeID uint32
	}

	testcases := []testcase{
		{[]byte("string"), uint32(base_mysql.TypeString)},
		{[]byte("bytes"), uint32(base_mysql.TypeBlob)},
		{[]byte("invalid_int32"), uint32(base_mysql.TypeLong)},
		{[]byte("invalid_int64"), uint32(base_mysql.TypeLongLong)},
	}

	column := "cossack_column"
	expectedError := base.NewEncodingError(column)

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", binaryFormat, -1, 0, 0)
		ctx := context.Background()
		setting := &config.BasicColumnEncryptionSetting{
			Name:           column,
			DataTypeID:     testcase.dataTypeID,
			ResponseOnFail: common.ResponseOnFailError,
		}
		logger := logrus.NewEntry(logrus.New())

		_, _, err := encoder.encodeBinary(ctx, testcase.input, setting, info, logger)

		if !errors.Is(err, expectedError) {
			t.Fatalf("expected error %q, but found %q", expectedError, err)
		}
	}
}

func TestValidateDefaultValue(t *testing.T) {
	type args struct {
		value      *string
		dataTypeID uint32
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
		{"invalid string", args{&invalidString, uint32(base_mysql.TypeString)}, true},
		{"valid bytes", args{&invalidString, uint32(base_mysql.TypeBlob)}, true},
		{"empty string", args{&emptyString, uint32(base_mysql.TypeString)}, false},
		{"empty bytes", args{&emptyString, uint32(base_mysql.TypeBlob)}, false},
		{"int32 string", args{&int32String, uint32(base_mysql.TypeString)}, false},
		{"invalid integer int32 string", args{&int64String, uint32(base_mysql.TypeLong)}, true},
		{"invalid non-integer int32 string", args{&someString, uint32(base_mysql.TypeLong)}, true},
		{"int64 string", args{&int64String, uint32(base_mysql.TypeLongLong)}, false},
		{"invalid int64 string", args{&invalidInt64String, uint32(base_mysql.TypeLongLong)}, true},
		{"invalid non-integer int64 string", args{&someString, uint32(base_mysql.TypeLongLong)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataTypeIDEncoders := type_awareness.GetMySQLDataTypeIDEncoders()
			encoder := dataTypeIDEncoders[tt.args.dataTypeID]

			if err := encoder.ValidateDefaultValue(tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("ValidateDefaultValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
