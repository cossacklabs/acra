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

// NewANSIMySQLDialect return new MySQLDialect
// TODO remove it after replacing with MySQLDialect + SetANSIMode
func NewANSIMySQLDialect() *MySQLDialect {
	return &MySQLDialect{ansiMode: true}
}

type DialectOption func(dialect *MySQLDialect)

func (dialect *MySQLDialect) SetANSIMode(ansiMode bool) {
	dialect.ansiMode = ansiMode
}

func (dialect *MySQLDialect) SetTableNameCaseSensitivity(sensitivity bool) {
	dialect.caseSensitiveTableName = sensitivity
}
