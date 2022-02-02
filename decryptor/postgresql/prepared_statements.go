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
	"errors"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/utils"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	tokens "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/sqlparser"
)

// Errors returned by prepared statement registry.
var (
	ErrStatementNotFound = errors.New("no prepared statement with given name")
	ErrCursorNotFound    = errors.New("no cursor with given name")
)

// PgPreparedStatementRegistry is a PostgreSQL PreparedStatementRegistry.
type PgPreparedStatementRegistry struct {
	statements map[string]base.PreparedStatement
	cursors    map[string]base.Cursor
}

// NewPreparedStatementRegistry makes a new empty prepared statement registry.
func NewPreparedStatementRegistry() *PgPreparedStatementRegistry {
	return &PgPreparedStatementRegistry{
		statements: make(map[string]base.PreparedStatement),
		cursors:    make(map[string]base.Cursor),
	}
}

// StatementByName returns a prepared statement from the registry by its name, if it exists.
func (r *PgPreparedStatementRegistry) StatementByName(name string) (base.PreparedStatement, error) {
	s, ok := r.statements[name]
	if ok {
		return s, nil
	}
	return nil, ErrStatementNotFound
}

// CursorByName returns a cursor from the registry by its name, if it exists.
func (r *PgPreparedStatementRegistry) CursorByName(name string) (base.Cursor, error) {
	s, ok := r.cursors[name]
	if ok {
		return s, nil
	}
	return nil, ErrCursorNotFound
}

// AddStatement adds a prepared statement to the registry.
// If an existing statement with the same name exists, it is replaced with the new one.
func (r *PgPreparedStatementRegistry) AddStatement(statement base.PreparedStatement) error {
	// TODO(ilammy, 2020-10-02): allow updates only for unnamed statements
	// PostgreSQL protocol allows repeated Parse messages (without matching Close)
	// only for unnamed prepared statements. SQL PREPARE cannot be repeated too.
	// Currently, Delete() is not called so we allow updates, but we shouldn't.
	name := statement.Name()
	// Remove everything associated with the old statement, like its cursors.
	err := r.DeleteStatement(name)
	if err != nil {
		return err
	}
	r.statements[name] = statement
	return nil
}

// AddCursor adds a cursor to the registry.
// If an existing cursor with the same name exists, it is replaced with the new one.
func (r *PgPreparedStatementRegistry) AddCursor(cursor base.Cursor) error {
	// TODO(ilammy, 2020-10-02): allow updates only for unnamed cursors
	// PostgreSQL protocol allows repeated Bind messages (without matching Close)
	// only for unnamed cursors. SQL DECLARE CURSOR cannot be repeated too.
	// Currently, Delete() is not called so we allow updates, but we shouldn't.
	name := cursor.Name()
	prepared := cursor.PreparedStatement()
	preparedName := prepared.Name()

	// It is an error to add a cursor for a statement which is not in the registry
	if expectedPrepared, ok := r.statements[preparedName]; !ok || expectedPrepared != prepared {
		return ErrStatementNotFound
	}

	// Add the cursor into the list of cursors for its prepared statement
	// and simultaneously enter it into the cursor registry.
	prepared.(*PgPreparedStatement).cursors[name] = cursor
	r.cursors[name] = cursor
	return nil
}

// DeleteStatement removes a statement with given name from the registry.
// It is not an error to remove nonexistent statements. In this case no error is returned and no action is taken.
// Removing a prepared statements removes all cursors associated with it.
func (r *PgPreparedStatementRegistry) DeleteStatement(name string) error {
	preparedGeneric, ok := r.statements[name]
	if !ok {
		return nil
	}
	prepared := preparedGeneric.(*PgPreparedStatement)

	// First, remove all cursors over the statement from the registry.
	for cursor := range prepared.cursors {
		delete(r.cursors, cursor)
	}
	// Then drop the cursor list of the statement.
	prepared.cursors = make(map[string]base.Cursor)
	// Followed by the statement itself
	delete(r.statements, name)
	return nil
}

// DeleteCursor removes a portals with given name from the registry.
// It is not an error to remove nonexistent portals. In this case no error is returned and no action is taken.
func (r *PgPreparedStatementRegistry) DeleteCursor(name string) error {
	cursor, ok := r.cursors[name]
	if !ok {
		return nil
	}
	// Remove the cursor from its prepared statement.
	prepared := cursor.PreparedStatement().(*PgPreparedStatement)
	delete(prepared.cursors, name)
	// Then remove it from the overall list of cursors.
	delete(r.cursors, name)
	return nil
}

// PgPreparedStatement is a PostgreSQL PreparedStatement.
type PgPreparedStatement struct {
	name string
	text string
	sql  sqlparser.Statement

	cursors map[string]base.Cursor
}

// NewPreparedStatement makes a new prepared statement.
func NewPreparedStatement(name string, text string, sql sqlparser.Statement) *PgPreparedStatement {
	return &PgPreparedStatement{
		name:    name,
		text:    text,
		sql:     sql,
		cursors: make(map[string]base.Cursor),
	}
}

// Name returns the name of the prepared statement.
func (s *PgPreparedStatement) Name() string {
	return s.name
}

// Query returns the prepared query, in its parsed form.
func (s *PgPreparedStatement) Query() sqlparser.Statement {
	return s.sql
}

// QueryText returns text of the prepared query, as provided by the client.
func (s *PgPreparedStatement) QueryText() string {
	return s.text
}

// ParamsNum return numbers of prepared statement params
func (s *PgPreparedStatement) ParamsNum() int {
	return 0
}

// PgPortal is a PostgreSQL Cursor.
// Cursors are called "portals" in PostgreSQL protocol specs.
type PgPortal struct {
	name      string
	statement base.PreparedStatement
}

// NewPortal makes a new portal.
func NewPortal(name string, statement base.PreparedStatement) *PgPortal {
	return &PgPortal{name, statement}
}

// Name returns the name of the cursor.
func (p *PgPortal) Name() string {
	return p.name
}

// PreparedStatement returns the prepared statement this cursor is associated with.
func (p *PgPortal) PreparedStatement() base.PreparedStatement {
	return p.statement
}

type pgBoundValue struct {
	data   []byte
	format base.BoundValueFormat
}

// NewPgBoundValue makes a pgsql BoundValue from copied input data.
func NewPgBoundValue(data []byte, format base.BoundValueFormat) base.BoundValue {
	var newData []byte
	if data != nil {
		newData = make([]byte, len(data))
		copy(newData, data)
	}

	return &pgBoundValue{newData, format}
}

// Copy create new base.BoundValue with copied data
func (p *pgBoundValue) Copy() base.BoundValue {
	return NewPgBoundValue(p.data, p.format)
}

// Format return BoundValue format
func (p *pgBoundValue) Format() base.BoundValueFormat {
	return p.format
}

// GetType stub for base.BoundValue method
func (p *pgBoundValue) GetType() byte {
	panic("implement me")
}

// SetData set new value to BoundValue using ColumnEncryptionSetting if provided
func (p *pgBoundValue) SetData(newData []byte, setting config.ColumnEncryptionSetting) error {
	if setting == nil {
		return nil
	}

	if setting.IsTokenized() {
		return p.setTokenizedData(newData, setting)
	} else if setting.OnlyEncryption() || setting.IsSearchable() {
		return p.setEncryptedData(newData, setting)
	}
	return nil
}

func (p *pgBoundValue) setTokenizedData(newData []byte, setting config.ColumnEncryptionSetting) error {
	p.data = newData
	switch p.format {
	case base.BinaryFormat:
		switch setting.GetTokenType()  {
		case tokens.TokenType_Int32:
			newVal, err := strconv.ParseInt(string(newData), 10, 32)
			if err != nil {
				return err
			}
			output := make([]byte, 4)
			binary.BigEndian.PutUint32(output[:], uint32(newVal))
			p.data = output
		case tokens.TokenType_Int64:
			newVal, err := strconv.ParseInt(string(newData), 10, 64)
			if err != nil {
				return err
			}
			output := make([]byte, 8)
			binary.BigEndian.PutUint64(output[:], uint64(newVal))
			p.data = output
		}
	}
	return nil
}

func (p *pgBoundValue) setEncryptedData(newData []byte, setting config.ColumnEncryptionSetting) error {
	p.data = newData
	switch p.format {
	case base.TextFormat:
		// here we take encrypted data and encode it to SQL String value that contains binary data in hex format
		// or pass it as is if it is already valid string (all other SQL literals)
		p.data = encryptor.PgEncodeToHexString(newData)
		return nil
	case base.BinaryFormat:
		// all our encryption operations applied over text format values to be compatible with text format
		// and here we work with encrypted TextFormat values that we should pass as is to server
		break
	}

	return nil
}

// GetData return BoundValue using ColumnEncryptionSetting if provided
func (p *pgBoundValue) GetData(setting config.ColumnEncryptionSetting) ([]byte, error) {
	if setting == nil {
		return p.data, nil
	}

	decodedData := p.data

	switch p.format {
	case base.TextFormat:
		if setting.OnlyEncryption() || setting.IsSearchable(){
			// binary data in TextFormat received as Hex/Octal encoded values
			// so we should decode them before processing
			switch setting.GetTokenType(){
			case tokens.TokenType_String, tokens.TokenType_Email:
				// TODO handle error
				decoded, err := utils.DecodeEscaped(p.data)
				if err != nil {
					return p.data, err
				}
				return decoded.Data(), nil
			}
		}
	// TODO(ilammy, 2020-10-19): handle non-bytes binary data
	// Encryptor expects binary data to be passed in raw bytes, but most non-byte-arrays
	// are expected in text format. If we get binary parameters, we may need to recode them.
	case base.BinaryFormat:
		if setting.IsTokenized() || setting.IsSearchable() || setting.OnlyEncryption() {
			switch setting.GetTokenType() {
			case tokens.TokenType_Int32:
				value := binary.BigEndian.Uint32(p.data)
				strValue := strconv.FormatInt(int64(value), 10)
				decodedData = []byte(strValue)
			case tokens.TokenType_Int64:
				// if passed int32 as int64, just extend array and fill by zeroes
				if len(p.data) == 4 {
					p.data = append([]byte{0, 0, 0, 0}, p.data...)
				}
				value := binary.BigEndian.Uint64(p.data)
				strValue := strconv.FormatInt(int64(value), 10)
				decodedData = []byte(strValue)
			}
		}
	}
	return decodedData, nil
}

// Encode format result BoundValue data
func (p pgBoundValue) Encode() ([]byte, error) {
	panic("implement me")
}
