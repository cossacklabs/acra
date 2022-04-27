package postgresql

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	common2 "github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// TestEncodingDecodingProcessorBinaryIntData checks decoding binary INT values to string SQL literals and back
func TestEncodingDecodingProcessorBinaryIntData(t *testing.T) {
	type testcase struct {
		binValue    []byte
		stringValue []byte
		encodeErr   error
		decodeErr   error
		binarySize  int
	}
	testcases := []testcase{
		// int32 without errors
		{binValue: []byte{0, 0, 0, 0}, stringValue: []byte("0"), encodeErr: nil, decodeErr: nil, binarySize: 4},
		{binValue: []byte{255, 255, 255, 255}, stringValue: []byte("-1"), encodeErr: nil, decodeErr: nil, binarySize: 4},
		{binValue: []byte{0, 0, 0, 128}, stringValue: []byte("128"), encodeErr: nil, decodeErr: nil, binarySize: 4},
		{binValue: []byte{255, 255, 255, 128}, stringValue: []byte("-128"), encodeErr: nil, decodeErr: nil, binarySize: 4},

		// int64 without errors
		{binValue: []byte{0, 0, 0, 0, 0, 0, 0, 0}, stringValue: []byte("0"), encodeErr: nil, decodeErr: nil, binarySize: 8},
		{binValue: []byte{255, 255, 255, 255, 255, 255, 255, 255}, stringValue: []byte("-1"), encodeErr: nil, decodeErr: nil, binarySize: 8},
		{binValue: []byte{0, 0, 0, 0, 0, 0, 0, 128}, stringValue: []byte("128"), encodeErr: nil, decodeErr: nil, binarySize: 8},
		{binValue: []byte{255, 255, 255, 255, 255, 255, 255, 128}, stringValue: []byte("-128"), encodeErr: nil, decodeErr: nil, binarySize: 8},
	}
	sizeToTokenType := map[int]string{
		4: "int32",
		8: "int64",
		// set correct values for incorrect sizes
		3: "int32",
		7: "int64",
	}

	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataDecoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	for i, tcase := range testcases {
		// use -1 as invalid binary size that should be ignored
		columnInfo := base.NewColumnInfo(0, "", true, -1, 0, 0)
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		ctx := base.SetAccessContextToContext(context.Background(), accessContext)
		testSetting := config.BasicColumnEncryptionSetting{
			DataType:  sizeToTokenType[tcase.binarySize],
			TokenType: sizeToTokenType[tcase.binarySize]}
		ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
		ctx, strData, err := decoder.OnColumn(ctx, tcase.binValue)
		if err != tcase.decodeErr {
			t.Fatalf("[%d] Expect %s, took %s\n", i, tcase.decodeErr, err)
		}
		if !bytes.Equal(tcase.stringValue, strData) {
			t.Fatalf("[%d] Expect '%s', took '%s'\n", i, tcase.stringValue, strData)
		}
		_, binData, err := encoder.OnColumn(ctx, strData)
		if err != tcase.encodeErr {
			t.Fatalf("[%d] Expect %s, took %s\n", i, tcase.encodeErr, err)
		}
		// we check that start value == final value only if err == nil and check success whole encoding/decoding
		if err == nil {
			if !bytes.Equal(binData, tcase.binValue) {
				t.Fatalf("[%d] Expect '%s', took '%s'\n", i, binData, tcase.binValue)
			}
		} else {
			// if was error then decoded data should be the same as encoded
			if !bytes.Equal(binData, tcase.stringValue) {
				t.Fatalf("[%d] Expect '%s', took '%s'\n", i, tcase.stringValue, binData)
			}
		}
	}
}

func TestSkipWithoutSetting(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataDecoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some data")
	for _, subscriber := range []base.DecryptionSubscriber{encoder, decoder} {
		// without column setting data
		ctx := context.Background()
		_, data, err := subscriber.OnColumn(ctx, testData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatal("Result data should be the same")
		}
		// test without column info
		columnSetting := &config.BasicColumnEncryptionSetting{}
		ctx = encryptor.NewContextWithEncryptionSetting(ctx, columnSetting)
		_, data, err = subscriber.OnColumn(ctx, testData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatal("Result data should be the same")
		}
	}
}

func TestTextMode(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataDecoderProcessor()
	if err != nil {
		t.Fatal(err)
	}

	type testcase struct {
		input       []byte
		decodedData []byte
		encodedData []byte
		decodeErr   error
		encodeErr   error
		setting     config.ColumnEncryptionSetting
		logMessage  string
	}
	strDefaultValue := "123"
	const stringWithControlCharacters = "#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'\"`abc"
	encodedStringWithControlCharacters := "\\x" + hex.EncodeToString([]byte("#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'\"`abc"))
	testcases := []testcase{
		// decoder expects valid string and pass as is, so no errors. but on encode operation it expects valid int literal
		{input: []byte("some data"), decodedData: []byte("some data"), encodedData: []byte("some data"),
			decodeErr: nil, encodeErr: nil,
			setting:    &config.BasicColumnEncryptionSetting{TokenType: "int32", DataType: "int32"},
			logMessage: `Can't decode int value and no default value`},

		{input: []byte("123"), decodedData: []byte("123"), encodedData: []byte("123"), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{TokenType: "int32", DataType: "int32"}},

		// encryption/decryption integer data, not tokenization
		{input: []byte("some data"), decodedData: []byte("some data"), encodedData: []byte("some data"), decodeErr: nil, encodeErr: nil,
			setting:    &config.BasicColumnEncryptionSetting{DataType: "int32"},
			logMessage: `Can't decode int value and no default value`},

		// encryption/decryption integer data, not tokenization
		{
			input:       []byte("some data"),
			decodedData: []byte("some data"),
			encodedData: []byte(strDefaultValue),
			decodeErr:   nil,
			encodeErr:   nil,
			setting: &config.BasicColumnEncryptionSetting{
				TokenType:        "int32",
				DataType:         "int32",
				ResponseOnFail:   common2.ResponseOnFailDefault,
				DefaultDataValue: &strDefaultValue,
			},
		},

		// string values can contain hex values and should be returned as is
		{input: []byte("\\xTT"), decodedData: []byte("\\xTT"), encodedData: []byte("\\xTT"), decodeErr: hex.InvalidByteError('T'), encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "str"}},

		// invalid binary hex value that should be returned as is. Also encoded into hex due to invalid hex value
		{input: []byte("\\xTT"), decodedData: []byte("\\xTT"), encodedData: []byte("\\x5c785454"), decodeErr: hex.InvalidByteError('T'), encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},

		{input: []byte(encodedStringWithControlCharacters), decodedData: []byte(stringWithControlCharacters), encodedData: []byte(encodedStringWithControlCharacters), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},

		{input: []byte(stringWithControlCharacters), decodedData: []byte(stringWithControlCharacters), encodedData: []byte(stringWithControlCharacters), decodeErr: nil, encodeErr: nil,
			setting: nil},
		{input: []byte(encodedStringWithControlCharacters), decodedData: []byte(stringWithControlCharacters), encodedData: []byte(stringWithControlCharacters), decodeErr: nil, encodeErr: nil,
			setting: nil},
		{input: []byte(stringWithControlCharacters), decodedData: []byte(stringWithControlCharacters), encodedData: []byte(stringWithControlCharacters), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: ""}},
		{input: []byte(encodedStringWithControlCharacters), decodedData: []byte(stringWithControlCharacters), encodedData: []byte(stringWithControlCharacters), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: ""}},

		{input: []byte("valid string"), decodedData: []byte("valid string"), encodedData: []byte("valid string"), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "str"}},

		// empty values
		{input: []byte{}, decodedData: []byte{}, encodedData: []byte{}, decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},
		// empty values
		{input: nil, decodedData: nil, encodedData: nil, decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},
		// empty values
		{input: []byte{}, decodedData: []byte{}, encodedData: []byte{}, decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "str"}},
		// empty values
		{input: nil, decodedData: nil, encodedData: nil, decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "str"}},
	}

	columnInfo := base.NewColumnInfo(0, "", false, 4, 0, 0)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	logger := logrus.New()
	entry := logrus.NewEntry(logger)
	logBuffer := &bytes.Buffer{}
	logger.SetOutput(logBuffer)
	ctx = logging.SetLoggerToContext(ctx, entry)
	for i, tcase := range testcases {
		logBuffer.Reset()
		ctx = encryptor.NewContextWithEncryptionSetting(ctx, tcase.setting)
		_, decodedData, decodeErr := decoder.OnColumn(ctx, tcase.input)
		if decodeErr != tcase.decodeErr {
			t.Fatalf("[%d] Incorrect decode error. Expect %s, took %s\n", i, tcase.decodeErr, decodeErr)
		}
		if !bytes.Equal(decodedData, tcase.decodedData) {
			t.Fatalf("[%d] Result data should be the same\n", i)
		}
		_, encodedData, encodeErr := encoder.OnColumn(ctx, decodedData)
		if encodeErr != tcase.encodeErr && !errors.As(encodeErr, &tcase.encodeErr) {
			t.Fatalf("[%d] Incorrect encode error. Expect %s, took %s\n", i, tcase.encodeErr.Error(), encodeErr.Error())
		}
		if !bytes.Equal(encodedData, tcase.encodedData) {
			t.Fatalf("[%d] Result data should be the same. Expect %s, took %s.\n", i, string(tcase.encodedData), string(encodedData))
		}
		if len(tcase.logMessage) > 0 && !strings.Contains(logBuffer.String(), tcase.logMessage) {
			t.Fatal("Log buffer doesn't contain expected message")
		}
	}
}

func TestBinaryMode(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataDecoderProcessor()
	if err != nil {
		t.Fatal(err)
	}

	type testcase struct {
		input       []byte
		decodedData []byte
		encodedData []byte
		decodeErr   error
		encodeErr   error
		setting     config.ColumnEncryptionSetting
		logMessage  string
	}
	strDefaultValue := "1"
	testcases := []testcase{
		// decoder expects valid string and pass as is, so no errors. but on encode operation it expects valid int literal
		{input: []byte("some data"), decodedData: []byte("some data"), encodedData: []byte("some data"),
			decodeErr: nil, encodeErr: nil,
			setting:    &config.BasicColumnEncryptionSetting{DataType: "int32"},
			logMessage: `Can't decode int value and no default value`},

		{input: []byte{0, 0, 0, 1}, decodedData: []byte("1"), encodedData: []byte{0, 0, 0, 1}, decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "int32"}},

		// encryption/decryption integer data, not tokenization
		{input: []byte("some data"), decodedData: []byte("some data"), encodedData: []byte("some data"), decodeErr: nil, encodeErr: nil,
			setting:    &config.BasicColumnEncryptionSetting{DataType: "int32"},
			logMessage: `Can't decode int value and no default value`},

		// encryption/decryption integer data, not tokenization
		{
			input:       []byte("some data"),
			decodedData: []byte("some data"),
			encodedData: []byte{0, 0, 0, 1},
			decodeErr:   nil,
			encodeErr:   nil,
			setting: &config.BasicColumnEncryptionSetting{
				DataType:         "int32",
				ResponseOnFail:   common2.ResponseOnFailDefault,
				DefaultDataValue: &strDefaultValue,
			},
		},

		// invalid binary hex value that should be returned as is. Also encoded into hex due to invalid hex value
		{input: []byte("\\xTT"), decodedData: []byte("\\xTT"), encodedData: []byte("\\xTT"), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},
		// printable valid value returned as is
		{input: []byte("valid string"), decodedData: []byte("valid string"), encodedData: []byte("valid string"), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},

		// empty values
		{input: []byte{}, decodedData: []byte{}, encodedData: []byte{}, decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},
		// empty values
		{input: nil, decodedData: nil, encodedData: nil, decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{DataType: "bytes"}},
	}

	columnInfo := base.NewColumnInfo(0, "", true, 4, 0, 0)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	logger := logrus.New()
	entry := logrus.NewEntry(logger)
	logBuffer := &bytes.Buffer{}
	logger.SetOutput(logBuffer)
	ctx = logging.SetLoggerToContext(ctx, entry)
	for i, tcase := range testcases {
		logBuffer.Reset()
		ctx = encryptor.NewContextWithEncryptionSetting(ctx, tcase.setting)
		_, decodedData, decodeErr := decoder.OnColumn(ctx, tcase.input)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("[%d]\n", i)
		if decodeErr != tcase.decodeErr {
			t.Fatalf("[%d] Incorrect decode error. Expect %s, took %s\n", i, tcase.decodeErr, decodeErr)
		}
		if !bytes.Equal(decodedData, tcase.decodedData) {
			t.Fatalf("[%d] Result data should be the same\n", i)
		}
		_, encodedData, encodeErr := encoder.OnColumn(ctx, decodedData)
		if encodeErr != tcase.encodeErr && !errors.As(encodeErr, &tcase.encodeErr) {
			t.Fatalf("[%d] Incorrect encode error. Expect %s, took %s\n", i, tcase.encodeErr.Error(), encodeErr.Error())
		}
		if !bytes.Equal(encodedData, tcase.encodedData) {
			t.Fatalf("[%d] Result data should be the same\n", i)
		}
		if len(tcase.logMessage) > 0 && !strings.Contains(logBuffer.String(), tcase.logMessage) {
			t.Fatalf("[%d] Log buffer doesn't contain expected message\n", i)
		}
	}
}

func TestEncodingDecodingTextFormatWithTokenType(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataDecoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	type testcase struct {
		inputValue  []byte
		outputValue []byte
		binValue    []byte
		tokenType   common.TokenType
	}
	testcases := []testcase{
		{inputValue: []byte(`valid string`), outputValue: []byte(`valid string`), binValue: []byte(`valid string`), tokenType: common.TokenType_String},
		// string values should be left as is
		{inputValue: []byte{0, 1, 2, 3}, outputValue: []byte{0, 1, 2, 3}, binValue: []byte{0, 1, 2, 3}, tokenType: common.TokenType_String},
		// valid string with newline\tab characters should be encoded as is
		{
			inputValue:  []byte("\n\t#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abc"),
			outputValue: []byte("\n\t#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abc"),
			binValue:    []byte("\n\t#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abc"),
			tokenType:   common.TokenType_String},
		// same for email
		{inputValue: []byte(`valid string`), outputValue: []byte(`valid string`), binValue: []byte(`valid string`), tokenType: common.TokenType_Email},
		// string values should be left as is
		{inputValue: []byte{0, 1, 2, 3}, outputValue: []byte{0, 1, 2, 3}, binValue: []byte{0, 1, 2, 3}, tokenType: common.TokenType_Email},
		// valid string with newline\tab characters should be encoded as is
		{
			inputValue:  []byte("\n\t#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abc"),
			outputValue: []byte("\n\t#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abc"),
			binValue:    []byte("\n\t#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abc"),
			tokenType:   common.TokenType_Email},

		// input hex encoded value that looks like a valid string should be returned as string literal
		{inputValue: []byte(`\x76616c696420737472696e67`), outputValue: []byte(`\x76616c696420737472696e67`), binValue: []byte(`valid string`), tokenType: common.TokenType_Bytes},
		{inputValue: []byte(`\x00010203`), outputValue: []byte(`\x00010203`), binValue: []byte{0, 1, 2, 3}, tokenType: common.TokenType_Bytes},

		// max int32
		{inputValue: []byte(`2147483647`), outputValue: []byte(`2147483647`), binValue: []byte(`2147483647`), tokenType: common.TokenType_Int32},
		{inputValue: []byte(`-2147483648`), outputValue: []byte(`-2147483648`), binValue: []byte(`-2147483648`), tokenType: common.TokenType_Int32},
		// max int64
		{inputValue: []byte(`9223372036854775807`), outputValue: []byte(`9223372036854775807`), binValue: []byte(`9223372036854775807`), tokenType: common.TokenType_Int64},
		{inputValue: []byte(`-9223372036854775808`), outputValue: []byte(`-9223372036854775808`), binValue: []byte(`-9223372036854775808`), tokenType: common.TokenType_Int64},
	}
	accessContext := &base.AccessContext{}
	// use -1 as invalid binary size that should be ignored
	columnInfo := base.NewColumnInfo(0, "", false, -1, 0, 0)
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	envelopeValue := config.CryptoEnvelopeTypeAcraBlock
	reencryptToAcraBlock := true
	// assign value with pointer and change value in the loop below
	for i, tcase := range testcases {
		columnInfo = base.NewColumnInfo(0, "", false, len(tcase.inputValue), 0, 0)
		accessContext.SetColumnInfo(columnInfo)
		testSetting := config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeValue, Name: "name", ReEncryptToAcraBlock: &reencryptToAcraBlock}
		ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
		testSetting.TokenType, err = tcase.tokenType.ToConfigString()
		if err != nil {
			t.Fatal(err)
		}
		if err := testSetting.Init(); err != nil {
			t.Fatal(err)
		}
		_, binValue, err := decoder.OnColumn(ctx, tcase.inputValue)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(binValue, tcase.binValue) {
			t.Fatalf("[%d] Expect binary value %s, took %s\n", i, string(tcase.binValue), string(binValue))
		}
		_, textValue, err := encoder.OnColumn(ctx, binValue)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(textValue, tcase.outputValue) {
			t.Fatalf("[%d] Expect text %s, took %s\n", i, string(textValue), string(tcase.inputValue))
		}
	}
}

func TestSkipWithoutColumnInfo(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataDecoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some data")
	accessContext := &base.AccessContext{}
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	testSetting := config.BasicColumnEncryptionSetting{TokenType: "int32"}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	for _, subscriber := range []base.DecryptionSubscriber{encoder, decoder} {
		_, data, err := subscriber.OnColumn(ctx, testData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatal("Result data should be the same")
		}
	}
}

func TestFailedEncodingInvalidTextValue(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	columnInfo := base.NewColumnInfo(0, "", true, 4, 0, 0)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	testSetting := config.BasicColumnEncryptionSetting{DataType: "int32"}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	testData := []byte("asdas")
	// without default value
	_, data, err := encoder.OnColumn(ctx, testData)
	if err != nil {
		t.Fatal("Expected nil on encode error")
	}
	if !bytes.Equal(data, testData) {
		t.Fatal("Result data should be the same")
	}

	// invalid int32 valid value
	strValue := utils.BytesToString(testData)
	testSetting = config.BasicColumnEncryptionSetting{
		DataType:         "int32",
		ResponseOnFail:   common2.ResponseOnFailDefault,
		DefaultDataValue: &strValue,
	}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	_, data, err = encoder.OnColumn(ctx, testData)
	if err != nil {
		t.Fatal("Expected nil on encode error")
	}
	if !bytes.Equal(data, testData) {
		t.Fatal("Result data should be the same")
	}
}

func TestFailedEncodingInvalidBinaryValue(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}
	columnInfo := base.NewColumnInfo(0, "", true, 4, 0, 0)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	testSetting := config.BasicColumnEncryptionSetting{DataType: "bytes"}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	testData := []byte("invalid base64 value")
	// without default value
	_, _, err = encoder.OnColumn(ctx, testData)
	if err != nil {
		t.Fatal("Expects nil on encode error")
	}

	// invalid int32 valid value
	strValue := utils.BytesToString(testData)
	testSetting = config.BasicColumnEncryptionSetting{
		DataType:         "bytes",
		ResponseOnFail:   common2.ResponseOnFailDefault,
		DefaultDataValue: &strValue,
	}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	logger := logrus.New()
	entry := logrus.NewEntry(logger)
	logBuffer := &bytes.Buffer{}
	logger.SetOutput(logBuffer)
	ctx = logging.SetLoggerToContext(ctx, entry)
	_, data, _ := encoder.OnColumn(ctx, testData)
	if !bytes.Contains(logBuffer.Bytes(), []byte("Can't decode base64 default value")) {
		t.Fatal("Expects warning about failed decoding")
	}
	if !bytes.Equal(data, testData) {
		t.Fatal("Result data should be the same")
	}
}

func TestErrorOnFail(t *testing.T) {
	markDecrypted := true
	markNotDecrypted := false

	type testcase struct {
		input     string
		dataType  string
		decrypted bool
		err       error
	}

	column := "gopher"

	// test all possible cases with happy and error paths with `response_on_fail = error`.
	// check only whether error is returned or not
	testcases := []testcase{
		// decryption successfull, we expect no error
		{"string_decrypted", "str", markDecrypted, nil},
		// decryption failed, we expect error
		{"string_not_decrypted", "str", markNotDecrypted, base.NewEncodingError(column)},

		// decryption successfull, we expect no error
		{"bytes_decrypted", "bytes", markDecrypted, nil},
		// decryption failed, we expect error
		{"bytes_not_decrypted", "bytes", markNotDecrypted, base.NewEncodingError(column)},

		// int doesn't care about marked context
		// valid int returns no error
		{"-2147483648", "int32", false, nil},
		// parsing error returns error
		{"invalid_int32", "int32", false, base.NewEncodingError(column)},

		{"-9223372036854775808", "int64", false, nil},
		{"invalid_int64", "int64", false, base.NewEncodingError(column)},

		// unknown type returns no error
		{"unknown_type_decrypted", "bees", markDecrypted, nil},
		{"unknown_type_not_decrypted", "bees", markNotDecrypted, nil},
	}

	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}

	for _, tcase := range testcases {
		testSetting := config.BasicColumnEncryptionSetting{
			Name:           column,
			DataType:       tcase.dataType,
			ResponseOnFail: common2.ResponseOnFailError,
		}
		ctx := encryptor.NewContextWithEncryptionSetting(context.Background(), &testSetting)
		if tcase.decrypted {
			ctx = base.MarkDecryptedContext(ctx)
		}

		// Text format
		columnInfo := base.NewColumnInfo(0, "", false, 4, 0, 0)
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		textCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, _, err = encoder.OnColumn(textCtx, []byte(tcase.input))
		if !errors.Is(err, tcase.err) {
			t.Fatalf("[%s] expected error=%q, but found %q", tcase.input, tcase.err, err)
		}

		// Binary format
		columnInfo = base.NewColumnInfo(0, "", true, 4, 0, 0)
		accessContext = &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		binaryCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, _, err = encoder.OnColumn(binaryCtx, []byte(tcase.input))
		if !errors.Is(err, tcase.err) {
			t.Fatalf("[%s] expected error=%q, but found %q", tcase.input, tcase.err, err)
		}
	}
}

func TestEmptyOnFail(t *testing.T) {
	type testcase struct {
		input    string
		dataType string
		output   string
	}

	testcases := []testcase{
		// we don't mark context as decrypted, to trigger
		// `OnFail` path
		{"string", "str", "string"},
		{"bytes", "bytes", "\\x6279746573"},
		{"invalid_int_32", "int32", "invalid_int_32"},
		{"invalid_int_64", "int64", "invalid_int_64"},
		{"unknown_type", "bees", "unknown_type"},
	}

	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}

	for _, tcase := range testcases {
		testSetting := config.BasicColumnEncryptionSetting{
			DataType:       tcase.dataType,
			ResponseOnFail: common2.ResponseOnFailEmpty,
		}
		ctx := encryptor.NewContextWithEncryptionSetting(context.Background(), &testSetting)

		// Text format
		columnInfo := base.NewColumnInfo(0, "", false, 4, 0, 0)
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		textCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, output, err := encoder.OnColumn(textCtx, []byte(tcase.input))
		if err != nil {
			t.Fatalf("[%s] %q", tcase.input, err)
		}
		if !bytes.Equal(output, []byte(tcase.output)) {
			t.Fatalf("[%s] expected output=%q, but found %q", tcase.input, tcase.input, output)
		}

		// Binary format
		columnInfo = base.NewColumnInfo(0, "", true, 4, 0, 0)
		accessContext = &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		binaryCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, output, err = encoder.OnColumn(binaryCtx, []byte(tcase.input))
		if err != nil {
			t.Fatalf("[%s] %q", tcase.input, err)
		}
		// in binary format expect value as is
		if !bytes.Equal(output, []byte(tcase.input)) {
			t.Fatalf("[%s] expected output=%q, but found %q", tcase.input, tcase.input, output)
		}
	}
}

func TestCiphertextOnFail(t *testing.T) {
	// The same as TestEmptyOnFail but `response_on_fail=ciphertext`

	type testcase struct {
		input    string
		dataType string
		output   string
	}

	testcases := []testcase{
		// we don't mark context as decrypted, to trigger
		// `OnFail` path
		{"string", "str", "string"},
		{"bytes", "bytes", "\\x6279746573"},
		{"invalid_int_32", "int32", "invalid_int_32"},
		{"invalid_int_64", "int64", "invalid_int_64"},
		{"unknown_type", "bees", "unknown_type"},
	}

	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}

	for _, tcase := range testcases {
		testSetting := config.BasicColumnEncryptionSetting{
			DataType:       tcase.dataType,
			ResponseOnFail: common2.ResponseOnFailCiphertext,
		}
		ctx := encryptor.NewContextWithEncryptionSetting(context.Background(), &testSetting)

		// Text format
		columnInfo := base.NewColumnInfo(0, "", false, 4, 0, 0)
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		textCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, output, err := encoder.OnColumn(textCtx, []byte(tcase.input))
		if err != nil {
			t.Fatalf("[%s] %q", tcase.input, err)
		}
		if !bytes.Equal(output, []byte(tcase.output)) {
			t.Fatalf("[%s] expected output=%q, but found %q", tcase.input, tcase.output, output)
		}

		// Binary format
		columnInfo = base.NewColumnInfo(0, "", true, 4, 0, 0)
		accessContext = &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		binaryCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, output, err = encoder.OnColumn(binaryCtx, []byte(tcase.input))
		if err != nil {
			t.Fatalf("[%s] %q", tcase.input, err)
		}
		// binary format expects as is
		if !bytes.Equal(output, []byte(tcase.input)) {
			t.Fatalf("[%s] expected output=%q, but found %q", tcase.input, tcase.input, output)
		}
	}
}

func TestDefaultOnFail(t *testing.T) {
	type testcase struct {
		input         string
		dataType      string
		defaultValue  string
		markDecrypted bool
		textOutput    []byte
		binaryOutput  []byte
	}

	testcases := []testcase{
		{
			input:         "string_decrypted",
			dataType:      "str",
			defaultValue:  "",
			markDecrypted: true,
			textOutput:    []byte("string_decrypted"),
			binaryOutput:  []byte("string_decrypted"),
		},

		{
			input:         "string_not_decrypted",
			dataType:      "str",
			defaultValue:  "default",
			markDecrypted: false,
			textOutput:    []byte("default"),
			binaryOutput:  []byte("default"),
		},

		{
			input:         "bytes_decrypted",
			dataType:      "bytes",
			defaultValue:  "",
			markDecrypted: true,
			textOutput:    []byte("\\x62797465735f646563727970746564"),
			binaryOutput:  []byte("bytes_decrypted"),
		},

		{
			input:         "bytes_not_decrypted",
			dataType:      "bytes",
			defaultValue:  "Y29zc2Fja2xhYnM=",
			markDecrypted: false,
			textOutput:    []byte("\\x636f737361636b6c616273"),
			binaryOutput:  []byte("cossacklabs"),
		},

		{
			input:         "bytes_not_decrypted_parse_error",
			dataType:      "bytes",
			defaultValue:  "добрий вечір",
			markDecrypted: false,
			textOutput:    []byte("\\x62797465735f6e6f745f6465637279707465645f70617273655f6572726f72"),
			binaryOutput:  []byte("bytes_not_decrypted_parse_error"),
		},

		{
			input:         "123456",
			dataType:      "int32",
			defaultValue:  "",
			markDecrypted: true,
			textOutput:    []byte("123456"),
			binaryOutput:  []byte{0x00, 0x01, 0xe2, 0x40},
		},

		{
			input:         "invalid_int32_decrypted",
			dataType:      "int32",
			defaultValue:  "",
			markDecrypted: true,
			textOutput:    []byte("invalid_int32_decrypted"),
			binaryOutput:  []byte("invalid_int32_decrypted"),
		},

		{
			input:         "invalid_int32_not_decrypted",
			dataType:      "int32",
			defaultValue:  "123456",
			markDecrypted: false,
			textOutput:    []byte("123456"),
			binaryOutput:  []byte{0x00, 0x01, 0xe2, 0x40},
		},

		{
			input:         "invalid_int32_invalid_default",
			dataType:      "int32",
			defaultValue:  "invalid_int32",
			markDecrypted: true,
			textOutput:    []byte("invalid_int32_invalid_default"),
			binaryOutput:  []byte("invalid_int32_invalid_default"),
		},

		{
			input:         "-987654",
			dataType:      "int64",
			defaultValue:  "",
			markDecrypted: true,
			textOutput:    []byte("-987654"),
			binaryOutput:  []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xed, 0xfa},
		},

		{
			input:         "invalid_int64_not_decrypted",
			dataType:      "int64",
			defaultValue:  "-987654",
			markDecrypted: false,
			textOutput:    []byte("-987654"),
			binaryOutput:  []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xed, 0xfa},
		},

		{
			input:         "invalid_int64_decrypted",
			dataType:      "int64",
			defaultValue:  "",
			markDecrypted: true,
			textOutput:    []byte("invalid_int64_decrypted"),
			binaryOutput:  []byte("invalid_int64_decrypted"),
		},

		{
			input:         "invalid_int64_invalid_default",
			dataType:      "int64",
			defaultValue:  "буль буль",
			markDecrypted: true,
			textOutput:    []byte("invalid_int64_invalid_default"),
			binaryOutput:  []byte("invalid_int64_invalid_default"),
		},

		{
			input:         "unknown_decrypted",
			dataType:      "some unknown type",
			defaultValue:  "",
			markDecrypted: true,
			// returns encoded value due to base feature of Acra is decryption AcraStructs/AcraBlocks even without config
			// due to existing acrawriter that allows to encrypt data on app's side
			textOutput:   []byte("\\x756e6b6e6f776e5f646563727970746564"),
			binaryOutput: []byte("unknown_decrypted"),
		},

		{
			input:         "unknown_not_decrypted",
			dataType:      "some unknown type",
			defaultValue:  "",
			markDecrypted: false,
			textOutput:    []byte("unknown_not_decrypted"),
			binaryOutput:  []byte("unknown_not_decrypted"),
		},
	}

	encoder, err := NewPgSQLDataEncoderProcessor()
	if err != nil {
		t.Fatal(err)
	}

	for _, tcase := range testcases {
		testSetting := config.BasicColumnEncryptionSetting{
			DataType:         tcase.dataType,
			ResponseOnFail:   common2.ResponseOnFailDefault,
			DefaultDataValue: &tcase.defaultValue,
		}
		ctx := encryptor.NewContextWithEncryptionSetting(context.Background(), &testSetting)
		if tcase.markDecrypted {
			ctx = base.MarkDecryptedContext(ctx)
		}

		// Text format
		columnInfo := base.NewColumnInfo(0, "", false, 4, 0, 0)
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		textCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, output, err := encoder.OnColumn(textCtx, []byte(tcase.input))
		if err != nil {
			t.Fatalf("[%s] %q", tcase.input, err)
		}
		if !bytes.Equal(output, []byte(tcase.textOutput)) {
			t.Fatalf("[%s] expected output=%q, but found %q", tcase.input, tcase.textOutput, output)
		}

		// Binary format
		columnInfo = base.NewColumnInfo(0, "", true, 4, 0, 0)
		accessContext = &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		binaryCtx := base.SetAccessContextToContext(ctx, accessContext)

		_, output, err = encoder.OnColumn(binaryCtx, []byte(tcase.input))
		if err != nil {
			t.Fatalf("[%s] %q", tcase.input, err)
		}
		if !bytes.Equal(output, []byte(tcase.binaryOutput)) {
			t.Fatalf(
				"[%s] expected output=%x (%q), but found %x (%q)",
				tcase.input,
				tcase.binaryOutput,
				tcase.binaryOutput,
				output,
				output,
			)
		}
	}
}
