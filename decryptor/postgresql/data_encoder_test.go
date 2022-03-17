package postgresql

import (
	"bytes"
	"context"
	"errors"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"strconv"
	"testing"
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

	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
	if err != nil {
		t.Fatal(err)
	}
	for i, tcase := range testcases {
		// use -1 as invalid binary size that should be ignored
		columnInfo := base.NewColumnInfo(0, "", true, -1)
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		ctx := base.SetAccessContextToContext(context.Background(), accessContext)
		testSetting := config.BasicColumnEncryptionSetting{
			Tokenized: true,
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

// TestEncodingDecodingProcessorAllowedBinaryData checks decoding binary array and string values to golang []byte and back
// String/Email/Byte types processed as is without any encoding/decoding
func TestEncodingDecodingProcessorAllowedBinaryData(t *testing.T) {
	validEmailString := []byte(`email@email.com`)
	type testcase struct {
		value     []byte
		tokenType common.TokenType
	}

	testcases := []testcase{
		// int32 without errors
		{value: validEmailString, tokenType: common.TokenType_String},
		{value: validEmailString, tokenType: common.TokenType_Email},
		{value: validEmailString, tokenType: common.TokenType_Bytes},
	}

	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
	if err != nil {
		t.Fatal(err)
	}
	for i, tcase := range testcases {
		columnInfo := base.NewColumnInfo(0, "", true, len(tcase.value))
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		ctx := base.SetAccessContextToContext(context.Background(), accessContext)
		testSetting := config.BasicColumnEncryptionSetting{Tokenized: true, TokenType: tcase.tokenType.String()}
		ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
		ctx, decodedValue, err := decoder.OnColumn(ctx, tcase.value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(validEmailString, decodedValue) {
			t.Fatalf("[%d] Expect '%s', took '%s'\n", i, validEmailString, decodedValue)
		}
		_, encodedData, err := encoder.OnColumn(ctx, decodedValue)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(validEmailString, encodedData) {
			t.Fatalf("[%d] Expect '%s', took '%s'\n", i, validEmailString, decodedValue)
		}
	}
}

func TestSkipWithoutSetting(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some data")
	for _, subscriber := range []base.DecryptionSubscriber{encoder, decoder} {
		_, data, err := subscriber.OnColumn(context.Background(), testData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, testData) {
			t.Fatal("Result data should be the same")
		}
	}
}

func TestTextMode(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
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
	}
	strDefaultValue := "123"
	testcases := []testcase{
		// decoder expects valid string and pass as is, so no errors. but on encode operation it expects valid int literal
		{input: []byte("some data"), decodedData: []byte("some data"), encodedData: []byte("some data"), decodeErr: nil, encodeErr: &strconv.NumError{},
			setting: &config.BasicColumnEncryptionSetting{Tokenized: true, DataType: "int32"}},

		{input: []byte("123"), decodedData: []byte("123"), encodedData: []byte("123"), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{Tokenized: true, DataType: "int32"}},

		// encryption/decryption integer data, not tokenization
		{input: []byte("some data"), decodedData: []byte("some data"), encodedData: []byte("some data"), decodeErr: nil, encodeErr: &strconv.NumError{},
			setting: &config.BasicColumnEncryptionSetting{Tokenized: false, DataType: "int32"}},

		// encryption/decryption integer data, not tokenization
		{input: []byte("some data"), decodedData: []byte("some data"), encodedData: []byte(strDefaultValue), decodeErr: nil, encodeErr: nil,
			setting: &config.BasicColumnEncryptionSetting{Tokenized: false, DataType: "int32", DefaultDataValue: &strDefaultValue}},
	}

	columnInfo := base.NewColumnInfo(0, "", false, 4)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	for i, tcase := range testcases {
		ctx = encryptor.NewContextWithEncryptionSetting(ctx, tcase.setting)
		_, decodedData, decodeErr := decoder.OnColumn(ctx, tcase.input)
		if err != nil {
			t.Fatal(err)
		}
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
	}
}

func TestEncodingDecodingTextFormat(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
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
		{inputValue: []byte(`valid string`), outputValue: []byte(`valid string`), binValue: []byte(`valid string`), tokenType: common.TokenType_Email},
		// input hex encoded value that looks like a valid string should be returned as string literal
		{inputValue: []byte(`\x76616c696420737472696e67`), outputValue: []byte(`valid string`), binValue: []byte(`valid string`), tokenType: common.TokenType_Bytes},

		// max int32
		{inputValue: []byte(`2147483647`), outputValue: []byte(`2147483647`), binValue: []byte(`2147483647`), tokenType: common.TokenType_Int32},
		{inputValue: []byte(`-2147483648`), outputValue: []byte(`-2147483648`), binValue: []byte(`-2147483648`), tokenType: common.TokenType_Int32},
		// max int64
		{inputValue: []byte(`9223372036854775807`), outputValue: []byte(`9223372036854775807`), binValue: []byte(`9223372036854775807`), tokenType: common.TokenType_Int64},
		{inputValue: []byte(`-9223372036854775808`), outputValue: []byte(`-9223372036854775808`), binValue: []byte(`-9223372036854775808`), tokenType: common.TokenType_Int64},
	}
	accessContext := &base.AccessContext{}
	// use -1 as invalid binary size that should be ignored
	columnInfo := base.NewColumnInfo(0, "", false, -1)
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	envelopeValue := config.CryptoEnvelopeTypeAcraBlock
	// assign value with pointer and change value in the loop below
	testSetting := config.BasicColumnEncryptionSetting{CryptoEnvelope: &envelopeValue}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	for i, tcase := range testcases {
		columnInfo = base.NewColumnInfo(0, "", false, len(tcase.inputValue))
		accessContext.SetColumnInfo(columnInfo)
		testSetting.TokenType, err = tcase.tokenType.ToConfigString()
		if err != nil {
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
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some data")
	accessContext := &base.AccessContext{}
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	testSetting := config.BasicColumnEncryptionSetting{Tokenized: true, TokenType: "int32"}
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

func TestEncodeDecodeModeValidation(t *testing.T) {
	// invalid mode
	_, err := NewPgSQLDataEncoderProcessor(3)
	if err != ErrInvalidDataEncoderMode {
		t.Fatalf("Expect ErrInvalidDataEncoderMode, took %s\n", err)
	}

	// create valid, but then change internally to invalid
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	// set invalid
	encoder.mode = 3
	testData := []byte("some data")
	columnInfo := base.NewColumnInfo(0, "", true, 4)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	testSetting := config.BasicColumnEncryptionSetting{Tokenized: true, TokenType: "int32"}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	_, _, err = encoder.OnColumn(ctx, testData)
	if err != ErrInvalidDataEncoderMode {
		t.Fatalf("Expect ErrInvalidDataEncoderMode, took %s\n", err)
	}
}

func TestFailedEncodingInvalidTextValue(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	columnInfo := base.NewColumnInfo(0, "", true, 4)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	testSetting := config.BasicColumnEncryptionSetting{Tokenized: true, TokenType: "int32"}
	ctx = encryptor.NewContextWithEncryptionSetting(ctx, &testSetting)
	testData := []byte("asdas")
	_, data, err := encoder.OnColumn(ctx, testData)
	numErr, ok := err.(*strconv.NumError)
	if !ok {
		t.Fatal("Expect strconv.NumError")
	}
	if numErr.Err != strconv.ErrSyntax {
		t.Fatalf("Expect ErrSyntax, took %s\n", numErr.Err)
	}
	if !bytes.Equal(data, testData) {
		t.Fatal("Result data should be the same")
	}
}
