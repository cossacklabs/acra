package acra_test

import (
	"github.com/cossacklabs/acra"
	"testing"
)

func testCorrectPgHexByteRead(reader *acra.PgHexByteReader, t *testing.T) {
	// 0xab == 171
	var expected_value byte = 171
	parsed, b, err := reader.ReadByte('a')
	if err != nil {
		t.Fatal("Unexpected error for correct any first byte")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}

	parsed, b, err = reader.ReadByte('b')
	if err != nil {
		t.Fatal("Unexpected error for correct second byte")
	}
	if !parsed {
		t.Fatal("Unexpected not parsed status")
	}

	if b != expected_value {
		t.Fatal("Incorrect parsing")
	}

	// invalid hex char
	parsed, b, err = reader.ReadByte('H')
	if err == nil {
		t.Fatal("Expected error but nil returned")
	}

	// valid hex char
	parsed, b, err = reader.ReadByte('F')
	if err != nil {
		t.Fatal("Unexpected error for any first byte")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}

	// invalid hex char
	parsed, b, err = reader.ReadByte('H')
	if err == nil {
		t.Fatal("Expected error for incorrect second byte")
	}
}

func testCorrectPgEscapeByteRead(reader *acra.PgEscapeByteReader, t *testing.T) {
	// 32-126 == 32-126
	// \047 == 39
	for c := 32; c <= 126; c++ {
		// skip '\' char because he returned not as is
		if c == 92 {
			continue
		}
		parsed, value, err := reader.ReadByte(byte(c))
		if err != nil {
			t.Fatal("Unexpected error")
		}
		if !parsed {
			t.Fatal("Unexpected unparsed status")
		}
		if byte(c) != value {
			t.Fatal("Incorrect parsed value")
		}
	}
	// first should be slash or any printable variable 32-126
	_, _, err := reader.ReadByte(byte(1))
	if err == nil {
		t.Fatal("Expected err, but nil returned")
	}

	parsed, _, err := reader.ReadByte('\\')
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}

	parsed, value, err := reader.ReadByte('\\')
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if !parsed {
		t.Fatal("Unexpected unparsed status")
	}
	if value != '\\' {
		t.Fatal("Incorrectly parsed value")
	}

	parsed, _, err = reader.ReadByte('\\')
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}

	// check parsing with incorrect first oct value
	parsed, _, err = reader.ReadByte('4')
	if err == nil {
		t.Fatal("Expected error but nil returned")
	}

	// check parsing with incorrect second oct value
	parsed, _, err = reader.ReadByte('\\')
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}
	parsed, _, err = reader.ReadByte('4')
	if err == nil {
		t.Fatal("Expected error but nil returned")
	}

	// check parsing with incorrect second oct value
	parsed, _, err = reader.ReadByte('\\')
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}
	parsed, _, err = reader.ReadByte('3')
	if err != nil {
		t.Fatal("Expected error but nil returned")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}
	_, _, err = reader.ReadByte('8')
	if err == nil {
		t.Fatal("Expected error but nil returned")
	}

	// check parsing with incorrect third oct value
	parsed, _, err = reader.ReadByte('\\')
	if err != nil {
		t.Fatal("Unexpected error")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}
	parsed, _, err = reader.ReadByte('3')
	if err != nil {
		t.Fatal("Expected error but nil returned")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}
	parsed, _, err = reader.ReadByte('3')
	if err != nil {
		t.Fatal("Expected error but nil returned")
	}
	if parsed {
		t.Fatal("Unexpected parsed status")
	}
	_, _, err = reader.ReadByte('8')
	if err == nil {
		t.Fatal("Expected error but nil returned")
	}
}

func TestPgHexByteReader(t *testing.T) {
	testCorrectPgHexByteRead(acra.NewPgHexByteReader(), t)
	testCorrectPgEscapeByteRead(acra.NewPgEscapeByteReader(), t)
}
