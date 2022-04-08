package config

import (
	"errors"
	"testing"

	common2 "github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/masking/common"
)

func TestCryptoEnvelopeDefaultValuesWithDefinedValue(t *testing.T) {
	testConfig := `
defaults:
  crypto_envelope: acrablock
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock
      - column: data3
        crypto_envelope: acrastruct
`
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	tableSchema := schemaStore.GetTableSchema("test_table")
	// check default value
	setting := tableSchema.GetColumnEncryptionSettings("data1")
	if setting.GetCryptoEnvelope() != CryptoEnvelopeTypeAcraBlock {
		t.Fatalf("Expect %s, took %s\n", CryptoEnvelopeTypeAcraBlock, setting.GetCryptoEnvelope())
	}

	// check same value as default
	setting = tableSchema.GetColumnEncryptionSettings("data2")
	if setting.GetCryptoEnvelope() != CryptoEnvelopeTypeAcraBlock {
		t.Fatalf("Expect %s, took %s\n", CryptoEnvelopeTypeAcraBlock, setting.GetCryptoEnvelope())
	}

	// check changed value
	setting = tableSchema.GetColumnEncryptionSettings("data3")
	if setting.GetCryptoEnvelope() != CryptoEnvelopeTypeAcraStruct {
		t.Fatalf("Expect %s, took %s\n", CryptoEnvelopeTypeAcraStruct, setting.GetCryptoEnvelope())
	}
}

func TestCryptoEnvelopeDefaultValuesWithoutDefinedValue(t *testing.T) {
	testConfig := `
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        crypto_envelope: acrablock
      - column: data3
        crypto_envelope: acrastruct
`
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	tableSchema := schemaStore.GetTableSchema("test_table")
	// check default value
	setting := tableSchema.GetColumnEncryptionSettings("data1")
	if setting.GetCryptoEnvelope() != CryptoEnvelopeTypeAcraBlock {
		t.Fatalf("Expect %s, took %s\n", CryptoEnvelopeTypeAcraStruct, setting.GetCryptoEnvelope())
	}

	// check same value as default
	setting = tableSchema.GetColumnEncryptionSettings("data2")
	if setting.GetCryptoEnvelope() != CryptoEnvelopeTypeAcraBlock {
		t.Fatalf("Expect %s, took %s\n", CryptoEnvelopeTypeAcraBlock, setting.GetCryptoEnvelope())
	}

	// check changed value
	setting = tableSchema.GetColumnEncryptionSettings("data3")
	if setting.GetCryptoEnvelope() != CryptoEnvelopeTypeAcraStruct {
		t.Fatalf("Expect %s, took %s\n", CryptoEnvelopeTypeAcraStruct, setting.GetCryptoEnvelope())
	}
}

func TestReEncryptAcraStructDefaultValuesWithDefinedValue(t *testing.T) {
	testConfig := `
defaults:
  reencrypting_to_acrablocks: false
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        reencrypting_to_acrablocks: false
      - column: data3
        reencrypting_to_acrablocks: true
`
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	tableSchema := schemaStore.GetTableSchema("test_table")
	// check default value
	setting := tableSchema.GetColumnEncryptionSettings("data1")
	if setting.ShouldReEncryptAcraStructToAcraBlock() {
		t.Fatalf("Expect %t on ShouldReEncryptAcraStructToAcraBlock()\n", false)
	}

	// check same value as default
	setting = tableSchema.GetColumnEncryptionSettings("data2")
	if setting.ShouldReEncryptAcraStructToAcraBlock() {
		t.Fatalf("Expect %t on ShouldReEncryptAcraStructToAcraBlock()\n", false)
	}

	// check changed value
	setting = tableSchema.GetColumnEncryptionSettings("data3")
	if !setting.ShouldReEncryptAcraStructToAcraBlock() {
		t.Fatalf("Expect %t on ShouldReEncryptAcraStructToAcraBlock()\n", true)
	}
}

func TestReEncryptAcraStructDefaultValuesWithoutDefinedValue(t *testing.T) {
	testConfig := `
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
    encrypted:
      - column: data1
      - column: data2
        reencrypting_to_acrablocks: true
      - column: data3
        reencrypting_to_acrablocks: false
`
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	tableSchema := schemaStore.GetTableSchema("test_table")
	// check default value
	setting := tableSchema.GetColumnEncryptionSettings("data1")
	if !setting.ShouldReEncryptAcraStructToAcraBlock() {
		t.Fatalf("Expect %t on ShouldReEncryptAcraStructToAcraBlock()\n", true)
	}

	// check same value as default
	setting = tableSchema.GetColumnEncryptionSettings("data2")
	if !setting.ShouldReEncryptAcraStructToAcraBlock() {
		t.Fatalf("Expect %t on ShouldReEncryptAcraStructToAcraBlock()\n", true)
	}

	// check changed value
	setting = tableSchema.GetColumnEncryptionSettings("data3")
	if setting.ShouldReEncryptAcraStructToAcraBlock() {
		t.Fatalf("Expect %t on ShouldReEncryptAcraStructToAcraBlock()\n", false)
	}
}

func TestInvalidMasking(t *testing.T) {
	type testcase struct {
		name   string
		config string
		err    error
	}
	testcases := []testcase{
		{"masking can't be searchable",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        masking: "xxxx"
        plaintext_length: 9
        plaintext_side: "right"
        searchable: true
`,
			ErrInvalidEncryptorConfig},

		{"plaintext_length should be > 0",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        masking: "xxxx"
        plaintext_length: -1
        plaintext_side: "right"
`,
			common.ErrInvalidPlaintextLength},

		{"invalid crypto_envelope",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        masking: "xxxx"
        plaintext_length: 5
        plaintext_side: "right"
        crypto_envelope: "invalid"
`,
			ErrInvalidCryptoEnvelopeType},

		{"should be specified plaintext_side",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        masking: "xxxx"
        plaintext_length: 9
`,
			common.ErrInvalidPlaintextSide},

		{"should be specified masking pattern",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        plaintext_length: 9
        plaintext_side: "right"
`,
			common.ErrInvalidMaskingPattern},

		{"searchable encryption doesn't support zones",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        searchable: true
        zone_id: DDDDDDDDMatNOMYjqVOuhACC
`,
			ErrInvalidEncryptorConfig},

		{"tokenization can't be searchable",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        tokenized: true
        searchable: true
`,
			//pseudonymization.ErrUnknownTokenType
			// use new declared to avoid cycle import
			errors.New("unknown token type")},

		{"invalid token type",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        tokenized: true
        token_type: invalid
`,
			// use new declared to avoid cycle import
			errors.New("unknown token type")},

		{"AcraBlock - type aware decryption, all supported types",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
      - column: data2
        data_type: bytes
      - column: data3
        data_type: int32
      - column: data4
        data_type: int64
`,
			nil},

		{"type aware decryption, all supported types + masking",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        masking: "00"
        plaintext_length: 2
        plaintext_side: "left"
      - column: data2
        data_type: bytes
        masking: "00"
        plaintext_length: 2
        plaintext_side: "left"
      - column: data3
        data_type: int32
      - column: data4
        data_type: int64
`,
			nil},

		{"type aware decryption, all supported types, specified client id",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        client_id: client
      - column: data2
        data_type: bytes
        client_id: client
      - column: data3
        data_type: int32
        client_id: client
      - column: data4
        data_type: int64
        client_id: client
`,
			nil},

		{"type aware decryption, all supported types, specified client id + masking",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        client_id: client
        masking: "00"
        plaintext_length: 2
        plaintext_side: "left"
      - column: data2
        data_type: bytes
        client_id: client
        masking: "00"
        plaintext_length: 2
        plaintext_side: "left"
      - column: data3
        data_type: int32
        client_id: client
      - column: data4
        data_type: int64
        client_id: client
`,
			nil},

		{"type aware decryption, all supported types, specified zone id",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        zone_id: client
      - column: data2
        data_type: bytes
        zone_id: client
      - column: data3
        data_type: int32
        zone_id: client
      - column: data4
        data_type: int64
        zone_id: client
`,
			nil},

		{"type aware decryption, all supported types, default value",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        response_on_fail: default
        default_data_value: "str"

      - column: data2
        data_type: bytes
        response_on_fail: default
        default_data_value: "bytes"

      - column: data3
        data_type: int32
        response_on_fail: default
        default_data_value: "123"

      - column: data4
        data_type: int64
        response_on_fail: default
        default_data_value: "123"
`,
			nil},

		{"type aware decryption, all supported types, default value, specified client id",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        response_on_fail: default
        default_data_value: "str"
        client_id: client

      - column: data2
        data_type: bytes
        response_on_fail: default
        default_data_value: "bytes"
        client_id: client

      - column: data3
        data_type: int32
        response_on_fail: default
        default_data_value: "123"
        client_id: client

      - column: data4
        data_type: int64
        response_on_fail: default
        default_data_value: "123"
        client_id: client
`,
			nil},

		{"type aware decryption, all supported types, default value, specified zone id",
			`
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        response_on_fail: default
        default_data_value: "str"
        zone_id: zone

      - column: data2
        data_type: bytes
        response_on_fail: default
        default_data_value: "bytes"
        zone_id: zone

      - column: data3
        data_type: int32
        response_on_fail: default
        default_data_value: "123"
        zone_id: zone

      - column: data4
        data_type: int64
        response_on_fail: default
        default_data_value: "123"
        zone_id: zone
`,
			nil},

		{"AcraBlock - type aware decryption, all supported types",
			`
defaults:
  crypto_envelope: acrastruct
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
      - column: data2
        data_type: bytes
      - column: data3
        data_type: int32
      - column: data4
        data_type: int64
`,
			nil},

		{"type aware decryption, all supported types, specified client id",
			`
defaults:
  crypto_envelope: acrastruct
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        client_id: client
      - column: data2
        data_type: bytes
        client_id: client
      - column: data3
        data_type: int32
        client_id: client
      - column: data4
        data_type: int64
        client_id: client
`,
			nil},

		{"type aware decryption, all supported types, specified zone id",
			`
defaults:
  crypto_envelope: acrastruct
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        zone_id: client
      - column: data2
        data_type: bytes
        zone_id: client
      - column: data3
        data_type: int32
        zone_id: client
      - column: data4
        data_type: int64
        zone_id: client
`,
			nil},

		{"type aware decryption, all supported types, default value",
			`
defaults:
  crypto_envelope: acrastruct
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        response_on_fail: default
        default_data_value: "str"

      - column: data2
        data_type: bytes
        response_on_fail: default
        default_data_value: "bytes"

      - column: data3
        data_type: int32
        response_on_fail: default
        default_data_value: "123"

      - column: data4
        data_type: int64
        response_on_fail: default
        default_data_value: "123"
`,
			nil},

		{"Acrastruct - type aware decryption, all supported types, default value, specified client id",
			`
defaults:
  crypto_envelope: acrastruct
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        response_on_fail: default
        default_data_value: "str"
        client_id: client

      - column: data2
        data_type: bytes
        response_on_fail: default
        default_data_value: "bytes"
        client_id: client

      - column: data3
        data_type: int32
        response_on_fail: default
        default_data_value: "123"
        client_id: client

      - column: data4
        data_type: int64
        response_on_fail: default
        default_data_value: "123"
        client_id: client
`,
			nil},

		{"type aware decryption, all supported types, default value, specified zone id",
			`
defaults:
  crypto_envelope: acrastruct
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        data_type: str
        response_on_fail: default
        default_data_value: "str"
        zone_id: zone

      - column: data2
        data_type: bytes
        response_on_fail: default
        default_data_value: "bytes"
        zone_id: zone

      - column: data3
        data_type: int32
        response_on_fail: default
        default_data_value: "123"
        zone_id: zone

      - column: data4
        data_type: int64
        response_on_fail: default
        default_data_value: "123"
        zone_id: zone
`,
			nil},
	}

	for _, tcase := range testcases {
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config))
		u, ok := err.(interface {
			Unwrap() error
		})
		if ok {
			err = u.Unwrap()
		}
		if tcase.err == err {
			continue
		}
		if tcase.err == nil {
			t.Fatalf("[%s] Expected nil, took %s\n", tcase.name, err)
		}

		if err == nil {
			t.Fatalf("[%s] Expected %s, took nil\n", tcase.name, tcase.err)
		}

		if err.Error() != tcase.err.Error() {
			t.Fatalf("[%s] Expect %s, took %s\n", tcase.name, tcase.err.Error(), err)
		}
	}
}

func TestDataTypeValidation(t *testing.T) {
	type testcase struct {
		config string
		err    error
	}
	testcases := []testcase{
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: int32
        tokenized: true
        token_type: int32
`,
			ErrInvalidEncryptorConfig},
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: int64
        tokenized: true
        token_type: int64
`,
			ErrInvalidEncryptorConfig},
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: str
        tokenized: true
        token_type: str
`,
			ErrInvalidEncryptorConfig},
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: bytes
        tokenized: true
        token_type: bytes
`,
			ErrInvalidEncryptorConfig},
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: str
        tokenized: true
        token_type: email
`,
			ErrInvalidEncryptorConfig},
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: int32
        tokenized: true
        token_type: str
`,
			ErrInvalidEncryptorConfig},
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: bytes
        tokenized: true
        token_type: str
`,
			ErrInvalidEncryptorConfig},
		{`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        data_type: bytes
        tokenized: true
        token_type: email
`,
			ErrInvalidEncryptorConfig},
	}
	for i, tcase := range testcases {
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config))
		u, ok := err.(interface {
			Unwrap() error
		})
		if ok {
			err = u.Unwrap()
		}
		if tcase.err == err {
			continue
		}
		if err.Error() != tcase.err.Error() {
			t.Fatalf("[%d] Expect %s, took %s\n", i, tcase.err.Error(), err)
		}
	}
}

func TestTypeAwarenessOnFailDefaults(t *testing.T) {
	type testcase struct {
		name   string
		onFail common2.ResponseOnFail
		config string
	}
	testcases := []testcase{
		{"By default, onFail is ''",
			"",
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data`},

		{"onFail is 'error' if data type is defined",
			"error",
			`
schemas:
  - table: test_table
    columns:
      - data_str
      - data_bytes
      - data_int32
      - data_int64
    encrypted:
      - column: data_str
        data_type: str
      - column: data_bytes
        data_type: bytes
      - column: data_int32
        data_type: int32
      - column: data_int64
        data_type: int64`},

		{"onFail is 'default' if explicitly defined",
			"default",
			`
  schemas:
    - table: test_table
      columns:
        - data_str
        - data_bytes
        - data_int32
        - data_int64
      encrypted:
        - column: data_str
          data_type: str
          response_on_fail: default
          default_data_value: string

        - column: data_bytes
          data_type: bytes
          response_on_fail: default
          default_data_value: Ynl0ZXM=

        - column: data_int32
          data_type: int32
          response_on_fail: default
          default_data_value: 2147483647

        - column: data_int64
          data_type: int64
          response_on_fail: default
          default_data_value: 9223372036854775807`},
	}

	for _, tcase := range testcases {
		config, err := MapTableSchemaStoreFromConfig([]byte(tcase.config))

		if err != nil {
			t.Fatalf("[%s] error=%s\n", tcase.name, err)
		}

		for _, column := range config.schemas["test_table"].EncryptionColumnSettings {
			if column.GetResponseOnFail() != tcase.onFail {
				t.Fatalf("[%s] GetResponseOnFail expected %q but found %q\n", tcase.name, tcase.onFail, column.GetResponseOnFail())
			}
		}
	}
}

func TestInvalidTypeAwarenessOnFailCombinations(t *testing.T) {
	type testcase struct {
		name   string
		config string
	}
	testcases := []testcase{
		{"OnFail=error and default",
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        data_type: str
        response_on_fail: error
        default_data_value: hidden by cossacklabs`},

		{"Only `default` without `response_on_fail`",
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        data_type: str
        default_data_value: hidden by cossacklabs`},

		{"OnFail=unknown",
			`
  schemas:
    - table: test_table
      columns:
        - data
      encrypted:
        - column: data
          data_type: str
          response_on_fail: unknown`},

		{"OnFail without data_type",
			`
      schemas:
        - table: test_table
          columns:
            - data
          encrypted:
            - column: data
              response_on_fail: error`},

		{"OnFail and default without data_type",
			`
              schemas:
                - table: test_table
                  columns:
                    - data
                  encrypted:
                    - column: data
                      response_on_fail: default
                      default_data_value: ukraine`},
	}

	for _, tcase := range testcases {
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config))

		if err == nil {
			t.Fatalf("[%s] expected error, found nil\n", tcase.name)
		}
	}
}
