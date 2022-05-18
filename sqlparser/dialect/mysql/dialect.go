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

// NewMySQLDialect return new MySQLDialect
func NewMySQLDialect(caseSensitiveTableName bool) *MySQLDialect {
	return &MySQLDialect{caseSensitiveTableName: caseSensitiveTableName}
}

// NewANSIMySQLDialect return new MySQLDialect
func NewANSIMySQLDialect() *MySQLDialect {
	return &MySQLDialect{ansiMode: true}
}
