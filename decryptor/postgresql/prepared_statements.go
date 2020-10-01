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
	registry map[string]base.PreparedStatement
}

// NewPreparedStatementRegistry makes a new empty prepared statement registry.
func NewPreparedStatementRegistry() *PgPreparedStatementRegistry {
	return &PgPreparedStatementRegistry{registry: make(map[string]base.PreparedStatement)}
}

// StatementByName returns a prepared statement from the registry by its name, if it exists.
func (r *PgPreparedStatementRegistry) StatementByName(name string) (base.PreparedStatement, error) {
	s, ok := r.registry[name]
	if ok {
		return s, nil
	}
	return nil, ErrStatementNotFound
}

// Add a statement to the registry. If an existing statement with the same name exists,
// it is replaced with the new one. Returns "true" if statement has been replaced.
func (r *PgPreparedStatementRegistry) Add(statement base.PreparedStatement) (bool, error) {
	name := statement.Name()
	_, exists := r.registry[name]
	r.registry[name] = statement
	return exists, nil
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

// PgPortalRegistry is a PostgreSQL CursorRegistry.
// Cursors are called "portals" in PostgreSQL protocol specs.
type PgPortalRegistry struct {
	registry map[string]base.Cursor
}

// NewPortalRegistry makes a new empty portal registry.
func NewPortalRegistry() *PgPortalRegistry {
	return &PgPortalRegistry{registry: make(map[string]base.Cursor)}
}

// CursorByName returns a cursor from the registry by its name, if it exists.
func (r *PgPortalRegistry) CursorByName(name string) (base.Cursor, error) {
	s, ok := r.registry[name]
	if ok {
		return s, nil
	}
	return nil, ErrCursorNotFound
}

// Add a portal to the registry. If an existing portal with the same name exists,
// it is replaced with the new one. Returns "true" if portal has been replaced.
func (r *PgPortalRegistry) Add(portal base.Cursor) (bool, error) {
	name := portal.Name()
	_, exists := r.registry[name]
	r.registry[name] = portal
	return exists, nil
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
