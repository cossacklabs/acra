package pseudonymization

import (
	"bytes"
	"context"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"strconv"
	"testing"
)

func TestEncodingDecodingProcessor(t *testing.T) {
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

		// int32 with invalid size. returned stringValue should be unchanged
		{binValue: []byte{255, 255, 255, 128}, stringValue: []byte("-128"), encodeErr: ErrInvalidIntValueBinarySize, decodeErr: nil, binarySize: 3},

		// int64 without errors
		{binValue: []byte{0, 0, 0, 0, 0, 0, 0, 0}, stringValue: []byte("0"), encodeErr: nil, decodeErr: nil, binarySize: 8},
		{binValue: []byte{255, 255, 255, 255, 255, 255, 255, 255}, stringValue: []byte("-1"), encodeErr: nil, decodeErr: nil, binarySize: 8},
		{binValue: []byte{0, 0, 0, 0, 0, 0, 0, 128}, stringValue: []byte("128"), encodeErr: nil, decodeErr: nil, binarySize: 8},
		{binValue: []byte{255, 255, 255, 255, 255, 255, 255, 128}, stringValue: []byte("-128"), encodeErr: nil, decodeErr: nil, binarySize: 8},

		// int64 with invalid size. returned stringValue should be unchanged
		{binValue: []byte{255, 255, 255, 255, 255, 255, 255, 128}, stringValue: []byte("-128"), encodeErr: ErrInvalidIntValueBinarySize, decodeErr: nil, binarySize: 7},
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
		columnInfo := base.NewColumnInfo(0, "", true, tcase.binarySize)
		accessContext := &base.AccessContext{}
		accessContext.SetColumnInfo(columnInfo)
		ctx := base.SetAccessContextToContext(context.Background(), accessContext)
		testSetting := config.BasicColumnEncryptionSetting{Tokenized: true, TokenType: sizeToTokenType[tcase.binarySize]}
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
		// we check that start value == final value only if err == nil and we check success whole encoding/decoding
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

func TestSkipWithoutBinaryMode(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some data")
	columnInfo := base.NewColumnInfo(0, "", false, 4)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
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

func TestSkipNotIntTokenType(t *testing.T) {
	encoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeEncode)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewPgSQLDataEncoderProcessor(DataEncoderModeDecode)
	if err != nil {
		t.Fatal(err)
	}
	testData := []byte("some data")
	columnInfo := base.NewColumnInfo(0, "", false, 4)
	accessContext := &base.AccessContext{}
	accessContext.SetColumnInfo(columnInfo)
	ctx := base.SetAccessContextToContext(context.Background(), accessContext)
	testSetting := config.BasicColumnEncryptionSetting{Tokenized: true, TokenType: "string"}
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
