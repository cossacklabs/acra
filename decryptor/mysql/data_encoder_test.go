package mysql

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/sirupsen/logrus"
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
		input    []byte
		dataType common.EncryptedType
		expected []byte
	}

	testcases := []testcase{
		{[]byte("string"), common.EncryptedType_String, []byte("\x06string")},
		{[]byte("bytes"), common.EncryptedType_Bytes, []byte("\x05bytes")},
		{[]byte("3200"), common.EncryptedType_Int32, []byte("\x80\f\x00\x00")},
		{[]byte("64000000"), common.EncryptedType_Int64, []byte("\x00\x90\xd0\x03\x00\x00\x00\x00")},
	}

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", binaryFormat, -1, 0, 0)
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
		dataType     common.EncryptedType
		defaultValue string
		expected     []byte
	}

	testcases := []testcase{
		{[]byte("string"), common.EncryptedType_String, "default_string", []byte("\x0edefault_string")},
		{[]byte("bytes"), common.EncryptedType_Bytes, "ZGVmYXVsdF9ieXRlcw==", []byte("\rdefault_bytes")},
		{[]byte("invalid_int32"), common.EncryptedType_Int32, "25519", []byte("\x0525519")},
		{[]byte("invalid_int64"), common.EncryptedType_Int64, "448", []byte("\x03448")},
	}

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", textFormat, -1, 0, 0)
		ctx := context.Background()
		dataType, err := testcase.dataType.ToConfigString()
		if err != nil {
			t.Fatal(err)
		}
		setting := &config.BasicColumnEncryptionSetting{
			DataType:         dataType,
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
		dataType     common.EncryptedType
		defaultValue string
		expected     []byte
	}

	testcases := []testcase{
		{[]byte("string"), common.EncryptedType_String, "default_string", []byte("\x0edefault_string")},
		{[]byte("bytes"), common.EncryptedType_Bytes, "ZGVmYXVsdF9ieXRlcw==", []byte("\rdefault_bytes")},
		{[]byte("invalid_int32"), common.EncryptedType_Int32, "25519", []byte("\xafc\x00\x00")},
		{[]byte("invalid_int64"), common.EncryptedType_Int64, "448", []byte("\xc0\x01\x00\x00\x00\x00\x00\x00")},
	}

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", binaryFormat, -1, 0, 0)
		ctx := context.Background()
		dataType, err := testcase.dataType.ToConfigString()
		if err != nil {
			t.Fatal(err)
		}
		setting := &config.BasicColumnEncryptionSetting{
			DataType:         dataType,
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
		input    []byte
		dataType common.EncryptedType
	}

	testcases := []testcase{
		{[]byte("string"), common.EncryptedType_String},
		{[]byte("bytes"), common.EncryptedType_Bytes},
		{[]byte("invalid_int32"), common.EncryptedType_Int32},
		{[]byte("invalid_int64"), common.EncryptedType_Int64},
	}

	column := "cossack_column"
	expectedError := base.NewEncodingError(column)

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", textFormat, -1, 0, 0)
		ctx := context.Background()
		dataType, err := testcase.dataType.ToConfigString()
		if err != nil {
			t.Fatal(err)
		}
		setting := &config.BasicColumnEncryptionSetting{
			Name:           column,
			DataType:       dataType,
			ResponseOnFail: common.ResponseOnFailError,
		}
		logger := logrus.NewEntry(logrus.New())

		_, _, err = encoder.encodeText(ctx, testcase.input, setting, info, logger)

		if !errors.Is(err, expectedError) {
			t.Fatalf("expected error %q, but found %q", expectedError, err)
		}
	}
}

func TestFailingBinaryEncodingWithEncodingError(t *testing.T) {
	type testcase struct {
		input    []byte
		dataType common.EncryptedType
	}

	testcases := []testcase{
		{[]byte("string"), common.EncryptedType_String},
		{[]byte("bytes"), common.EncryptedType_Bytes},
		{[]byte("invalid_int32"), common.EncryptedType_Int32},
		{[]byte("invalid_int64"), common.EncryptedType_Int64},
	}

	column := "cossack_column"
	expectedError := base.NewEncodingError(column)

	for _, testcase := range testcases {
		fmt.Printf("-- case %q\n", testcase.input)

		encoder := NewDataEncoderProcessor()

		info := base.NewColumnInfo(0, "", binaryFormat, -1, 0, 0)
		ctx := context.Background()
		dataType, err := testcase.dataType.ToConfigString()
		if err != nil {
			t.Fatal(err)
		}
		setting := &config.BasicColumnEncryptionSetting{
			Name:           column,
			DataType:       dataType,
			ResponseOnFail: common.ResponseOnFailError,
		}
		logger := logrus.NewEntry(logrus.New())

		_, _, err = encoder.encodeBinary(ctx, testcase.input, setting, info, logger)

		if !errors.Is(err, expectedError) {
			t.Fatalf("expected error %q, but found %q", expectedError, err)
		}
	}
}
