package config

import (
	"errors"
	"github.com/cossacklabs/acra/masking/common"
	"testing"
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
		config string
		err    error
	}
	testcases := []testcase{
		// masking can't be searchable
		{`
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
		// plaintext_length should be > 0
		{`
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
		// invalid crypto_envelope
		{`
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
		// should be specified plaintext_side
		{`
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
		// should be specified masking pattern
		{`
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
		// searchable encryption doesn't support zones
		{`
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
		// tokenization can't be searchable
		{`
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
		{`
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

		// AcraBlock
		// type aware decryption, all supported types
		{`
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
		// type aware decryption, all supported types + masking
		{`
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
		// type aware decryption, all supported types, specified client id
		{`
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
		// type aware decryption, all supported types, specified client id + masking
		{`
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
		// type aware decryption, all supported types, specified zone id
		{`
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
		// type aware decryption, all supported types, default value
		{`
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
        default_data_value: "str"
      - column: data2
        data_type: bytes
        default_data_value: "bytes"
      - column: data3
        data_type: int32
        default_data_value: "123"
      - column: data4
        data_type: int64
        default_data_value: "123"
`,
			nil},
		// type aware decryption, all supported types, default value, specified client id
		{`
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
        default_data_value: "str"
        client_id: client
      - column: data2
        data_type: bytes
        default_data_value: "bytes"
        client_id: client
      - column: data3
        data_type: int32
        default_data_value: "123"
        client_id: client
      - column: data4
        data_type: int64
        default_data_value: "123"
        client_id: client
`,
			nil},
		// type aware decryption, all supported types, default value, specified zone id
		{`
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
        default_data_value: "str"
        zone_id: zone
      - column: data2
        data_type: bytes
        default_data_value: "bytes"
        zone_id: zone
      - column: data3
        data_type: int32
        default_data_value: "123"
        zone_id: zone
      - column: data4
        data_type: int64
        default_data_value: "123"
        zone_id: zone
`,
			nil},
		// AcraBlock
		// type aware decryption, all supported types
		{`
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
		// type aware decryption, all supported types, specified client id
		{`
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
		// type aware decryption, all supported types, specified zone id
		{`
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
		// type aware decryption, all supported types, default value
		{`
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
        default_data_value: "str"
      - column: data2
        data_type: bytes
        default_data_value: "bytes"
      - column: data3
        data_type: int32
        default_data_value: "123"
      - column: data4
        data_type: int64
        default_data_value: "123"
`,
			nil},
		// type aware decryption, all supported types, default value, specified client id
		{`
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
        default_data_value: "str"
        client_id: client
      - column: data2
        data_type: bytes
        default_data_value: "bytes"
        client_id: client
      - column: data3
        data_type: int32
        default_data_value: "123"
        client_id: client
      - column: data4
        data_type: int64
        default_data_value: "123"
        client_id: client
`,
			nil},
		// type aware decryption, all supported types, default value, specified zone id
		{`
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
        default_data_value: "str"
        zone_id: zone
      - column: data2
        data_type: bytes
        default_data_value: "bytes"
        zone_id: zone
      - column: data3
        data_type: int32
        default_data_value: "123"
        zone_id: zone
      - column: data4
        data_type: int64
        default_data_value: "123"
        zone_id: zone
`,
			nil},
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
