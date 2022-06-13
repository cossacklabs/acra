package postgresql

import (
	"github.com/cossacklabs/acra/sqlparser/dialect"
)

// PostgreSQLDialect dialect implementation for PostgreSQL
type PostgreSQLDialect struct{}

// QuoteHandler return QuoteHandler for PostgreSQL
func (dialect *PostgreSQLDialect) QuoteHandler() dialect.QuoteHandler {
	return NewQuoteHandler()
}

// NewPostgreSQLDialect dialect for PostgreSQL
func NewPostgreSQLDialect(options ...DialectOption) *PostgreSQLDialect {
	pgDialect := &PostgreSQLDialect{}
	for _, option := range options {
		option(pgDialect)
	}
	return pgDialect
}

// DialectOption is used to enable different options in dialect and thus tune SQL parser behavior
type DialectOption func(dialect *PostgreSQLDialect)
