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
	"fmt"
	"strconv"

	pg_query "github.com/Zhaars/pg_query_go/v4"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/base/config/common"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	tokens "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/utils"
)

// Errors returned by prepared statement registry.
var (
	ErrStatementNotFound = errors.New("no prepared statement with given name")
	ErrCursorNotFound    = errors.New("no cursor with given name")
)

// PgPreparedStatementRegistry is a PostgreSQL PreparedStatementRegistry.
type PgPreparedStatementRegistry struct {
	statements map[string]base.PgPreparedStatement
	cursors    map[string]base.Cursor
}

// NewPreparedStatementRegistry makes a new empty prepared statement registry.
func NewPreparedStatementRegistry() *PgPreparedStatementRegistry {
	return &PgPreparedStatementRegistry{
		statements: make(map[string]base.PgPreparedStatement),
		cursors:    make(map[string]base.Cursor),
	}
}

// StatementByName returns a prepared statement from the registry by its name, if it exists.
func (r *PgPreparedStatementRegistry) StatementByName(name string) (base.PgPreparedStatement, error) {
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
func (r *PgPreparedStatementRegistry) AddStatement(statement base.PgPreparedStatement) error {
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

	// if new cursor overrides existing, zeroize data in previous
	oldCursor, ok := r.cursors[name]
	if ok {
		oldCursor.(*PgPortal).bind.Zeroize()
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
	for cursorName, cursor := range prepared.cursors {
		cursor.(*PgPortal).bind.Zeroize()
		delete(r.cursors, cursorName)
	}
	// Then drop the cursor list of the statement.
	prepared.cursors = make(map[string]base.Cursor)
	prepared.text = ""
	// TODO: lagovas (10.02.2023) zeroize sql prepared.statement with recursive walking through SQLNodes
	// and overwriting bytes

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
	stmt *pg_query.Node

	cursors map[string]base.Cursor
}

// NewPreparedStatement makes a new prepared statement.
func NewPreparedStatement(name string, text string, stmt *pg_query.Node) *PgPreparedStatement {
	return &PgPreparedStatement{
		name:    name,
		text:    text,
		stmt:    stmt,
		cursors: make(map[string]base.Cursor),
	}
}

// Name returns the name of the prepared statement.
func (s *PgPreparedStatement) Name() string {
	return s.name
}

// Query returns the prepared query, in its parsed form.
func (s *PgPreparedStatement) Query() *pg_query.Node {
	return s.stmt
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
	bind      *BindPacket
	statement base.PgPreparedStatement
}

// NewPortal makes a new portal.
func NewPortal(bind *BindPacket, statement base.PgPreparedStatement) *PgPortal {
	return &PgPortal{bind, statement}
}

// Name returns the name of the cursor.
func (p *PgPortal) Name() string {
	return p.bind.PortalName()
}

// PreparedStatement returns the prepared statement this cursor is associated with.
func (p *PgPortal) PreparedStatement() base.PgPreparedStatement {
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
		p.data = newData
		return nil
	}

	if setting.IsTokenized() {
		return p.setTokenizedData(newData, setting)
	} else if config.IsBinaryDataOperation(setting) {
		return p.setEncryptedData(newData, setting)
	}
	return nil
}

func (p *pgBoundValue) setTokenizedData(newData []byte, setting config.ColumnEncryptionSetting) error {
	p.data = newData
	switch p.format {
	case base.TextFormat:
		// here we take encrypted data and encode it to SQL String value that contains binary data in hex format
		// or pass it as is if it is already valid string (all other SQL literals)
		if utils.IsPrintablePostgresqlString(newData) {
			p.data = newData
		} else {
			p.data = postgresql.PgEncodeToHexString(newData)
		}
		return nil
	case base.BinaryFormat:
		switch setting.GetTokenType() {
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
		if utils.IsPrintablePostgresqlString(newData) {
			p.data = newData
		} else {
			p.data = postgresql.PgEncodeToHexString(newData)
		}
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
		if setting.OnlyEncryption() || setting.IsSearchable() || setting.IsConsistentTokenization() {
			// binary data in TextFormat received as Hex/Octal encoded values
			// so we should decode them before processing

			decoded, err := utils.DecodeEscaped(p.data)
			if err != nil {
				return p.data, err
			}
			return decoded, nil
		}
	case base.BinaryFormat:
		if setting.IsTokenized() || setting.IsSearchable() || setting.OnlyEncryption() {
			switch setting.GetEncryptedDataType() {
			case common.EncryptedType_Int32, common.EncryptedType_Int64:
				var value int64
				switch len(p.data) {
				// We don't directly suport smallint, but at least we handle them
				// during insertion
				case 2:
					// explicitly set number to signed, so expansion to int64 will
					// be correct in case of negative numbers
					intValue := int16(binary.BigEndian.Uint16(p.data))
					value = int64(intValue)
				case 4:
					intValue := int32(binary.BigEndian.Uint32(p.data))
					value = int64(intValue)
				case 8:
					value = int64(binary.BigEndian.Uint64(p.data))
				default:
					err := fmt.Errorf("unexpected number of bytes in number: %d", len(p.data))
					return []byte{}, err
				}
				strValue := strconv.FormatInt(value, 10)
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
