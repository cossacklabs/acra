package mysql

import "github.com/cossacklabs/acra/sqlparser/dialect"

// MySQLDialect dialect implementation for MySQL
type MySQLDialect struct {
	ansiMode               bool
	caseSensitiveTableName bool
}

// IsModeANSIOn return true if ANSI mode used for mysql
func (dialect *MySQLDialect) IsModeANSIOn() bool {
	return dialect.ansiMode
}

// IsCaseSensitiveTableName return true if case sensitivity is enabled for table identifiers
func (dialect *MySQLDialect) IsCaseSensitiveTableName() bool {
	return dialect.caseSensitiveTableName
}

// QuoteHandler return correct dialect according to sql mode
func (dialect *MySQLDialect) QuoteHandler() dialect.QuoteHandler {
	if dialect.ansiMode {
		return NewANSIQuoteHandler()
	}
	return NewDefaultQuoteHandler()
}

// NewMySQLDialect return new MySQLDialect, optionally configured with additional options
func NewMySQLDialect(options ...DialectOption) *MySQLDialect {
	mysqlDialect := &MySQLDialect{}
	for _, option := range options {
		option(mysqlDialect)
	}
	return mysqlDialect
}

// DialectOption is used to enable different options in dialect and thus tune SQL parser behavior
type DialectOption func(dialect *MySQLDialect)

// SetANSIMode allows to enable ANSI mode
func SetANSIMode(ansiMode bool) DialectOption {
	return func(dialect *MySQLDialect) {
		dialect.ansiMode = ansiMode
	}
}

// SetTableNameCaseSensitivity allows to enable case sensitivity for table identifiers
func SetTableNameCaseSensitivity(sensitivity bool) DialectOption {
	return func(dialect *MySQLDialect) {
		dialect.caseSensitiveTableName = sensitivity
	}
}
