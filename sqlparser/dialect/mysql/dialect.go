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

type DialectOption func(dialect *MySQLDialect)

func SetANSIMode(ansiMode bool) DialectOption {
	return func(dialect *MySQLDialect) {
		dialect.ansiMode = ansiMode
	}
}

func SetTableNameCaseSensitivity(sensitivity bool) DialectOption {
	return func(dialect *MySQLDialect) {
		dialect.caseSensitiveTableName = sensitivity
	}
}
