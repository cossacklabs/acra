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
	"errors"

	"github.com/cossacklabs/acra/decryptor/base"
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
	portals    map[string]base.Cursor
}

// NewPreparedStatementRegistry makes a new empty prepared statement registry.
func NewPreparedStatementRegistry() *PgPreparedStatementRegistry {
	return &PgPreparedStatementRegistry{
		statements: make(map[string]base.PreparedStatement),
		portals:    make(map[string]base.Cursor),
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
	s, ok := r.portals[name]
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
	r.statements[name] = statement
	return nil
}

// AddCursor adds a portal to the registry.
// If an existing portal with the same name exists, it is replaced with the new one.
func (r *PgPreparedStatementRegistry) AddCursor(portal base.Cursor) error {
	// TODO(ilammy, 2020-10-02): allow updates only for unnamed portals
	// PostgreSQL protocol allows repeated Bind messages (without matching Close)
	// only for unnamed portals. SQL DECLARE CURSOR cannot be repeated too.
	// Currently, Delete() is not called so we allow updates, but we shouldn't.
	name := portal.Name()
	r.portals[name] = portal
	return nil
}

// PgPreparedStatement is a PostgreSQL PreparedStatement.
type PgPreparedStatement struct {
	name string
	text string
	sql  sqlparser.Statement
}

// NewPreparedStatement makes a new prepared statement.
func NewPreparedStatement(name string, text string, sql sqlparser.Statement) *PgPreparedStatement {
	return &PgPreparedStatement{name, text, sql}
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

// PgPortal is a PostgreSQL Cursor.
// Cursors are called "portals" in PostgreSQL protocol specs.
type PgPortal struct {
	name      string
	statement *PgPreparedStatement
}

// NewPortal makes a new portal.
func NewPortal(name string, statement *PgPreparedStatement) *PgPortal {
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
