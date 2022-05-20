/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package postgresql

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
)

func TestStatementInsert(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	statement := NewPreparedStatement("statement", "SELECT 1", nil)

	// There is no such statement in the registry initially.
	initialStatement, err := registry.StatementByName("statement")
	if err != ErrStatementNotFound {
		t.Error("unexpected error when looking for missing statement", err)
	}
	if initialStatement != nil {
		t.Error("unexpected statement in empty registry", initialStatement)
	}

	// Now add it...
	err = registry.AddStatement(statement)
	if err != nil {
		t.Fatal("cannot add initial statement", err)
	}

	// And it should be there as a result.
	foundStatement, err := registry.StatementByName("statement")
	if err != nil {
		t.Fatal("cannot look up statement after add", err)
	}
	if foundStatement != statement {
		t.Error("did not find the same statement")
	}
}

func TestStatementUpdateNamed(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	// Insert a statement into the registry.
	statement1 := NewPreparedStatement("statement", "SELECT 1", nil)
	err := registry.AddStatement(statement1)
	if err != nil {
		t.Fatal("cannot add initial statement", err)
	}

	// Then do it again, using the same name.
	statement2 := NewPreparedStatement("statement", "SELECT 2", nil)
	err = registry.AddStatement(statement2)
	if err != nil {
		t.Fatal("cannot update existing named statement", err)
	}

	// The statement should be updated.
	foundStatement, err := registry.StatementByName("statement")
	if err != nil {
		t.Fatal("cannot look up statement after update", err)
	}
	if foundStatement != statement2 {
		t.Error("did not find the same statement")
	}
}

func TestCursorInsertion(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	statement := NewPreparedStatement("statement", "SELECT * FROM TEST", nil)
	cursor := NewPortal("cursor", statement)

	// It should not be possible to add a cursor into the registry
	// without its associated statement already being there.
	err := registry.AddCursor(cursor)
	if err != ErrStatementNotFound {
		t.Error("unexpected error when adding cursor without statement", err)
	}

	// And of course there is no such cursor in the registry initially.
	initialCursor, err := registry.CursorByName("cursor")
	if err != ErrCursorNotFound {
		t.Error("unexpected error when looking for missing cursor", err)
	}
	if initialCursor != nil {
		t.Error("unexpected cursor in empty registry", initialCursor)
	}

	// Now, add the statement and its cursor into the registry.
	err = registry.AddStatement(statement)
	if err != nil {
		t.Fatal("cannot add statement", err)
	}
	err = registry.AddCursor(cursor)
	if err != nil {
		t.Fatal("cannot add cursor", err)
	}

	// The cursor should be available by its name after that.
	foundCursor, err := registry.CursorByName("cursor")
	if err != nil {
		t.Fatal("cannot look up cursor after add", err)
	}
	if foundCursor != cursor {
		t.Error("did not find the same cursor")
	}
}

func TestCursorUpdateNamed(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	// Insert a cursor into the registry.
	statement := NewPreparedStatement("statement", "SELECT 1", nil)
	err := registry.AddStatement(statement)
	if err != nil {
		t.Fatal("cannot add initial statement", err)
	}
	cursor1 := NewPortal("cursor", statement)
	err = registry.AddCursor(cursor1)
	if err != nil {
		t.Fatal("cannot add cursor", err)
	}

	// Then create a new cursor for the same statement and insert it again.
	cursor2 := NewPortal("cursor", statement)
	err = registry.AddCursor(cursor2)
	if err != nil {
		t.Fatal("cannot update existing named cursor", err)
	}

	// The cursor should be updated.
	foundCursor, err := registry.CursorByName("cursor")
	if err != nil {
		t.Fatal("cannot look up cursor after update", err)
	}
	if foundCursor != cursor2 {
		t.Error("did not find the same cursor")
	}

	// Now, the same should work just fine if a cursor for different statement reuses the same name,
	// provided that the statement is in the registry and all.
	statement2 := NewPreparedStatement("statement", "SELECT 2", nil)
	cursor3 := NewPortal("cursor", statement2)
	err = registry.AddStatement(statement2)
	if err != nil {
		t.Fatal("cannot add second statement", err)
	}
	err = registry.AddCursor(cursor3)
	if err != nil {
		t.Fatal("cannot update existing named cursor again", err)
	}
	// And it should point to that different cursor.
	foundCursor3, err := registry.CursorByName("cursor")
	if err != nil {
		t.Fatal("cannot look up cursor after update", err)
	}
	if foundCursor3 != cursor3 {
		t.Error("did not find the same cursor")
	}
}

func TestStatementRemoval(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	// Insert some statement into the registry.
	statement := NewPreparedStatement("statement", "SELECT 1", nil)
	err := registry.AddStatement(statement)
	if err != nil {
		t.Fatal("cannot add initial statement", err)
	}

	// Quickly remove it...
	err = registry.DeleteStatement("statement")
	if err != nil {
		t.Fatal("cannot remove statement", err)
	}

	// There should be no statement now.
	notFoundStatement, err := registry.StatementByName("statement")
	if err != ErrStatementNotFound {
		t.Error("unexpected error when looking for removed statement", err)
	}
	if notFoundStatement != nil {
		t.Error("unexpected non-nil removed statement", notFoundStatement)
	}
}

func TestStatementRemovalMissing(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	// It's okay to remove the statement which was not there in the first place
	// since it is allowed by PostgreSQL protocol.
	err := registry.DeleteStatement("missing")
	if err != nil {
		t.Error("cannot remove missing statement", err)
	}
}

func TestCursorRemoval(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	// Insert some statement and cursors into the registry.
	statement := NewPreparedStatement("statement", "SELECT 1", nil)
	err := registry.AddStatement(statement)
	if err != nil {
		t.Fatal("cannot add initial statement", err)
	}
	cursor1 := NewPortal("cursor1", statement)
	err = registry.AddCursor(cursor1)
	if err != nil {
		t.Fatal("cannot add cursor", err)
	}
	cursor2 := NewPortal("cursor2", statement)
	err = registry.AddCursor(cursor2)
	if err != nil {
		t.Fatal("cannot add cursor", err)
	}

	// Remove one of the cursors.
	err = registry.DeleteCursor("cursor1")
	if err != nil {
		t.Fatal("cannot remove cursor", err)
	}

	// Removed cursor should not be present now.
	notFoundCursor, err := registry.CursorByName("cursor1")
	if err != ErrCursorNotFound {
		t.Error("unexpected error when looking for removed cursor", err)
	}
	if notFoundCursor != nil {
		t.Error("unexpected non-nil removed cursor", notFoundCursor)
	}

	// Though, the other cursor should still be there.
	foundCursor, err := registry.CursorByName("cursor2")
	if err != nil {
		t.Fatal("failed to get surviving cursor", err)
	}
	if foundCursor != cursor2 {
		t.Error("unexpected surviving cursor", foundCursor)
	}
}

func TestCursorRemovalMissing(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	// It's okay to remove the cursor which was not there in the first place
	// since it is allowed by PostgreSQL protocol.
	err := registry.DeleteCursor("missing")
	if err != nil {
		t.Error("cannot remove missing cursor", err)
	}
}

func TestCursorRemovalWithStatement(t *testing.T) {
	registry := NewPreparedStatementRegistry()

	// Insert some statement and cursors into the registry.
	statement := NewPreparedStatement("statement", "SELECT 1", nil)
	err := registry.AddStatement(statement)
	if err != nil {
		t.Fatal("cannot add initial statement", err)
	}
	cursor1 := NewPortal("cursor1", statement)
	err = registry.AddCursor(cursor1)
	if err != nil {
		t.Fatal("cannot add cursor", err)
	}
	cursor2 := NewPortal("cursor2", statement)
	err = registry.AddCursor(cursor2)
	if err != nil {
		t.Fatal("cannot add cursor", err)
	}

	// Remove the statement
	err = registry.DeleteStatement("statement")
	if err != nil {
		t.Fatal("cannot remove statement", err)
	}

	// This should also axe all of its cursors.
	notFoundCursor1, err := registry.CursorByName("cursor1")
	if err != ErrCursorNotFound {
		t.Error("unexpected error when looking for removed cursor", err)
	}
	if notFoundCursor1 != nil {
		t.Error("unexpected non-nil removed cursor", notFoundCursor1)
	}
	notFoundCursor2, err := registry.CursorByName("cursor2")
	if err != ErrCursorNotFound {
		t.Error("unexpected error when looking for removed cursor", err)
	}
	if notFoundCursor2 != nil {
		t.Error("unexpected non-nil removed cursor", notFoundCursor2)
	}
}

func TestNewPgBoundValue(t *testing.T) {
	t.Run("textData not equals - success", func(t *testing.T) {
		sourceData := []byte("test-data")
		boundValue := NewPgBoundValue(sourceData, base.BinaryFormat)

		sourceData[0] = 22
		value, err := boundValue.GetData(nil)
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(sourceData, value) {
			t.Fatal("BoundValue data should not be equal to sourceData")
		}
	})

	t.Run("nil data provided", func(t *testing.T) {
		boundValue := NewPgBoundValue(nil, base.BinaryFormat)
		value, err := boundValue.GetData(nil)
		if err != nil {
			t.Fatal(err)
		}
		// we need to validate that textData is nil if nil was provided - required for handling NULL values
		if value != nil {
			t.Fatal("BoundValue data should be nil")
		}
	})
}

func i16ToBe(value int) []byte {
	result := [2]byte{}
	binary.BigEndian.PutUint16(result[:], uint16(value))
	return result[:]
}

func i32ToBe(value int) []byte {
	result := [4]byte{}
	binary.BigEndian.PutUint32(result[:], uint32(value))
	return result[:]
}

func i64ToBe(value int) []byte {
	result := [8]byte{}
	binary.BigEndian.PutUint64(result[:], uint64(value))
	return result[:]
}

func TestPgBoundIntBinaryEncoding(t *testing.T) {
	type testcase struct {
		data     []byte
		output   string
		dataType string
	}

	testcases := []testcase{
		{i32ToBe(0), "0", "int32"},
		{i32ToBe(123), "123", "int32"},
		{i32ToBe(-123), "-123", "int32"},
		{i32ToBe(2147483647), "2147483647", "int32"},
		{i32ToBe(-2147483648), "-2147483648", "int32"},
		{i32ToBe(32767), "32767", "int32"},
		{i32ToBe(-32768), "-32768", "int32"},

		{i32ToBe(0), "0", "int64"},
		{i32ToBe(123), "123", "int64"},
		{i32ToBe(-123), "-123", "int64"},
		{i32ToBe(2147483647), "2147483647", "int64"},
		{i32ToBe(-2147483648), "-2147483648", "int64"},
		{i32ToBe(32767), "32767", "int64"},
		{i32ToBe(-32768), "-32768", "int64"},

		{i64ToBe(0), "0", "int64"},
		{i64ToBe(123), "123", "int64"},
		{i64ToBe(-123), "-123", "int64"},
		{i64ToBe(2147483647), "2147483647", "int64"},
		{i64ToBe(-2147483648), "-2147483648", "int64"},
		{i64ToBe(32767), "32767", "int64"},
		{i64ToBe(-32768), "-32768", "int64"},
		{i64ToBe(22147483647), "22147483647", "int64"},
		{i64ToBe(-222147483648), "-222147483648", "int64"},
		{i64ToBe(9223372036854775807), "9223372036854775807", "int64"},
		{i64ToBe(-9223372036854775808), "-9223372036854775808", "int64"},

		{i16ToBe(0), "0", "int32"},
		{i16ToBe(53), "53", "int32"},
		{i16ToBe(-53), "-53", "int32"},
		{i16ToBe(0), "0", "int32"},
		{i16ToBe(127), "127", "int32"},
		{i16ToBe(-128), "-128", "int32"},

		{i16ToBe(0), "0", "int64"},
		{i16ToBe(53), "53", "int64"},
		{i16ToBe(-53), "-53", "int64"},
		{i16ToBe(0), "0", "int64"},
		{i16ToBe(127), "127", "int64"},
		{i16ToBe(-128), "-128", "int64"},
	}

	for i, tcase := range testcases {
		fmt.Printf("===> [%d] %q [%x] (%s)\n", i, tcase.output, tcase.data, tcase.dataType)
		value := pgBoundValue{data: tcase.data, format: base.BinaryFormat}
		settings := config.BasicColumnEncryptionSetting{
			DataType: tcase.dataType,
		}
		serialized, err := value.GetData(&settings)
		if err != nil {
			t.Fatal(err)
		}
		if string(serialized) != tcase.output {
			t.Fatalf("%q != %q (expected)", serialized, tcase.output)
		}
	}
}
