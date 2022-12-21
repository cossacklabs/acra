package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	common2 "github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/masking/common"
	"github.com/jackc/pgx/pgtype"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig), UseMySQL)
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

func TestConsistentTokenizationDefaultValuesWithDefinedValue(t *testing.T) {
	testConfig := `
defaults:
  consistent_tokenization: true
schemas:
  - table: test_table
    columns:
      - data1
      - data2
      - data3
      - data4
    encrypted:
      - column: data1
        token_type: str
      - column: data2
        token_type: int64
      - column: data3
        token_type: int32
      - column: data4
        token_type: int32
        consistent_tokenization: false
`
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig), UseMySQL)
	if err != nil {
		t.Fatal(err)
	}
	tableSchema := schemaStore.GetTableSchema("test_table")
	// check default value
	setting := tableSchema.GetColumnEncryptionSettings("data1")
	if !setting.GetConsistentTokenization() {
		t.Fatalf("Expect consistent tokenization to be true, but got false: %s", "data1")
	}

	// check same value as default
	setting = tableSchema.GetColumnEncryptionSettings("data2")
	if !setting.GetConsistentTokenization() {
		t.Fatalf("Expect consistent tokenization to be true, but got false: %s", "data2")
	}

	setting = tableSchema.GetColumnEncryptionSettings("data3")
	if !setting.GetConsistentTokenization() {
		t.Fatalf("Expect consistent tokenization to be true, but got false: %s", "data3")
	}

	// expect different value on forced consistent_tokenization
	setting = tableSchema.GetColumnEncryptionSettings("data4")
	if setting.GetConsistentTokenization() {
		t.Fatalf("Expect consistent tokenization to be false, but got true: %s", "data4")
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
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig), UseMySQL)
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
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig), UseMySQL)
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
	schemaStore, err := MapTableSchemaStoreFromConfig([]byte(testConfig), UseMySQL)
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
	registerMySQLDummyEncoders()

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

		{"tokenization can't be searchable",
			`
schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        token_type: int32
        searchable: true
`,
			errors.New("invalid encryptor config")},

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
        response_on_fail: default_value
        default_data_value: "str"

      - column: data2
        data_type: bytes
        response_on_fail: default_value
        default_data_value: "bytes"

      - column: data3
        data_type: int32
        response_on_fail: default_value
        default_data_value: "123"

      - column: data4
        data_type: int64
        response_on_fail: default_value
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
        response_on_fail: default_value
        default_data_value: "str"
        client_id: client

      - column: data2
        data_type: bytes
        response_on_fail: default_value
        default_data_value: "bytes"
        client_id: client

      - column: data3
        data_type: int32
        response_on_fail: default_value
        default_data_value: "123"
        client_id: client

      - column: data4
        data_type: int64
        response_on_fail: default_value
        default_data_value: "123"
        client_id: client
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
        response_on_fail: default_value
        default_data_value: "str"

      - column: data2
        data_type: bytes
        response_on_fail: default_value
        default_data_value: "bytes"

      - column: data3
        data_type: int32
        response_on_fail: default_value
        default_data_value: "123"

      - column: data4
        data_type: int64
        response_on_fail: default_value
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
        response_on_fail: default_value
        default_data_value: "str"
        client_id: client

      - column: data2
        data_type: bytes
        response_on_fail: default_value
        default_data_value: "bytes"
        client_id: client

      - column: data3
        data_type: int32
        response_on_fail: default_value
        default_data_value: "123"
        client_id: client

      - column: data4
        data_type: int64
        response_on_fail: default_value
        default_data_value: "123"
        client_id: client
`,
			nil},
	}

	for _, tcase := range testcases {
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config), UseMySQL)
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
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config), UseMySQL)
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
		{"By default, onFail is 'ciphertext'",
			common2.ResponseOnFailCiphertext,
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data`},

		{"onFail is 'ciphertext' if data type is defined",
			common2.ResponseOnFailCiphertext,
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

		{"onFail is 'default_vaue' if explicitly defined",
			common2.ResponseOnFailDefault,
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
        response_on_fail: default_value
        default_data_value: string

      - column: data_bytes
        data_type: bytes
        response_on_fail: default_value
        default_data_value: Ynl0ZXM=

      - column: data_int32
        data_type: int32
        response_on_fail: default_value
        default_data_value: 2147483647

      - column: data_int64
        data_type: int64
        response_on_fail: default_value
        default_data_value: 9223372036854775807`},

		{"onFail is 'error' if explicitly defined",
			common2.ResponseOnFailError,
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
        response_on_fail: error

      - column: data_bytes
        data_type: bytes
        response_on_fail: error

      - column: data_int32
        data_type: int32
        response_on_fail: error

      - column: data_int64
        data_type: int64
        response_on_fail: error`},

		{"onFail is implicitly 'default_value' if 'default_data_value' is defined",
			common2.ResponseOnFailDefault,
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
      default_data_value: string

    - column: data_bytes
      data_type: bytes
      default_data_value: Ynl0ZXM=

    - column: data_int32
      data_type: int32
      default_data_value: 2147483647

    - column: data_int64
      data_type: int64
      default_data_value: 9223372036854775807`},
	}

	for _, tcase := range testcases {
		config, err := MapTableSchemaStoreFromConfig([]byte(tcase.config), UseMySQL)

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
        response_on_fail: default_value
        default_data_value: ukraine`},
		{"OnFai=ciphertext and default",
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        data_type: str
        response_on_fail: ciphertext
        default_data_value: oops`},
	}

	for _, tcase := range testcases {
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config), UseMySQL)

		if err == nil {
			t.Fatalf("[%s] expected error, found nil\n", tcase.name)
		}
	}
}

func TestDeprecateTokenized(t *testing.T) {
	tokenTypes := []string{
		"str", "email", "int64", "int32", "bytes",
	}

	for _, token := range tokenTypes {
		config := fmt.Sprintf(`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        tokenized: true
        token_type: %s
`, token)
		_, err := MapTableSchemaStoreFromConfig([]byte(config), UseMySQL)
		if err != nil {
			t.Fatalf("[tokenize: true, token_type: %s] %s", token, err)
		}

		config = fmt.Sprintf(`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        token_type: %s
`, token)
		_, err = MapTableSchemaStoreFromConfig([]byte(config), UseMySQL)
		if err != nil {
			t.Fatalf("[token_type: %s] %s", token, err)
		}

		config = fmt.Sprintf(`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        consistent_tokenization: true
        token_type: %s
`, token)
		_, err = MapTableSchemaStoreFromConfig([]byte(config), UseMySQL)
		if err != nil {
			t.Fatalf("[consistent_tokenization: true, token_type: %s] %s", token, err)
		}
	}
}

func TestInvalidTokenizationCombinations(t *testing.T) {
	type testcase struct {
		name   string
		config string
	}
	testcases := []testcase{
		{"Tokenized: false and token_type non empty",
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        tokenized: false
        token_type: str
    `},
		{"tokenized: true without token_type",
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        tokenized: true
  `},

		{"tokenized: true with empty token_type",
			`
schemas:
  - table: test_table
    columns:
      - data
    encrypted:
      - column: data
        tokenized: true
        token_type: ""
  `},
	}

	for _, tcase := range testcases {
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config), UseMySQL)

		if err == nil {
			t.Fatalf("[%s] expected error, found nil\n", tcase.name)
		}
	}
}

func TestTokenizedDeprecationWarning(t *testing.T) {
	config := `
    schemas:
      - table: test_table
        columns:
          - data
        encrypted:
          - column: data
            tokenized: true
            token_type: str`

	buff := bytes.NewBuffer([]byte{})
	log.SetOutput(buff)
	_, err := MapTableSchemaStoreFromConfig([]byte(config), UseMySQL)
	if err != nil {
		t.Fatal(err)
	}

	output := buff.Bytes()
	msg := "Setting `tokenized` flag is not necessary anymore and will be ignored"
	if !bytes.Contains(output, []byte(msg)) {
		t.Fatal("warning is not found but expected")
	}
}

func TestWithDataTypeIDOption(t *testing.T) {
	type testcase struct {
		name   string
		config string
	}
	testcases := []testcase{
		{
			name: "Schema store with data_type_db_identifier",
			config: `
schemas:
  - table: test_type_aware_decryption_with_defaults
    columns:
      - id
      - value_str
    
    encrypted:
      - column: value_str
        data_type_db_identifier: 25
`,
		},
		{
			name: "Schema store with data_type_db_identifier and on_fail options",
			config: `
schemas:
  - table: test_type_aware_decryption_with_defaults
    columns:
      - id
      - value_str

    encrypted:
      - column: value_str
        data_type_db_identifier: 25
        response_on_fail: default_value
        default_data_value: "value_str"
`,
		},
	}

	type_awareness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.TextOID, &dummyDataTypeEncoder{})

	for _, tcase := range testcases {
		schemaStore, err := MapTableSchemaStoreFromConfig([]byte(tcase.config), UsePostgreSQL)
		if err != nil {
			t.Fatal(err)
		}

		dataTypeID := schemaStore.GetTableSchema("test_type_aware_decryption_with_defaults").
			GetColumnEncryptionSettings("value_str").GetDBDataTypeID()
		assert.Equal(t, dataTypeID, uint32(25))
	}
}

func TestInvalidWithDataTypeIDOption(t *testing.T) {
	type testcase struct {
		name          string
		config        string
		expectedError error
	}
	testcases := []testcase{
		{
			name:          "Schema store with data_type_db_identifier and data_type options",
			expectedError: common2.ErrDataTypeWithDataTypeID,
			config: `
schemas:
  - table: test_type_aware_decryption_with_defaults
    columns:
      - id
      - value_str
    
    encrypted:
      - column: value_str
        data_type: str
        data_type_db_identifier: 25
`,
		},
		{
			name: "Schema store with not supported data_type options",
			config: `
schemas:
  - table: test_type_aware_decryption_with_defaults
    columns:
      - id
      - value_str
    
    encrypted:
      - column: value_str
        data_type_db_identifier: 10
`,
			expectedError: common2.ErrUnsupportedDataTypeID,
		},
	}

	type_awareness.RegisterPostgreSQLDataTypeIDEncoder(pgtype.TextOID, nil)

	for _, tcase := range testcases {
		_, err := MapTableSchemaStoreFromConfig([]byte(tcase.config), UsePostgreSQL)
		if err == nil {
			t.Fatalf("expected got error on invalid config - %s", tcase.name)
		}

		if err != tcase.expectedError {
			t.Fatalf("expected got error %s - but found %s", tcase.expectedError.Error(), err.Error())
		}
	}
}

func registerMySQLDummyEncoders() {
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeBlob), &dummyDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeString), &dummyDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeLong), &dummyDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeLongLong), &dummyDataTypeEncoder{})
}

type dummyDataTypeEncoder struct{}

// Encode implementation of Encode method of DataTypeEncoder interface for TypeLong
func (t *dummyDataTypeEncoder) Encode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return nil, nil, nil
}

// Decode implementation of Decode method of DataTypeEncoder interface for TypeLong
func (t *dummyDataTypeEncoder) Decode(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return nil, nil, nil
}

// EncodeOnFail implementation of EncodeOnFail method of DataTypeEncoder interface for TypeLong
func (t *dummyDataTypeEncoder) EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return nil, nil, nil
}

// EncodeDefault implementation of EncodeDefault method of DataTypeEncoder interface for TypeLong
func (t *dummyDataTypeEncoder) encodeDefault(ctx context.Context, data []byte, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	return nil, nil, nil
}

// ValidateDefaultValue implementation of ValidateDefaultValue method of DataTypeEncoder interface for TypeLong
func (t *dummyDataTypeEncoder) ValidateDefaultValue(value *string) error {
	return nil
}
