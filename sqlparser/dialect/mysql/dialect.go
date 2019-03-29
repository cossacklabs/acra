package mysql

import "github.com/cossacklabs/acra/sqlparser/dialect"

// MySQLDialect dialect implementation for MySQL
type MySQLDialect struct {
	ansiMode bool
}

// QuoteHandler return correct dialect according to sql mode
func (dialect *MySQLDialect) QuoteHandler() dialect.QuoteHandler {
	if dialect.ansiMode {
		return NewANSIQuoteHandler()
	}
	return NewDefaultQuoteHandler()
}

// NewMySQLDialect return new MySQLDialect
func NewMySQLDialect() *MySQLDialect {
	return &MySQLDialect{}
}

// NewANSIMySQLDialect return new MySQLDialect
func NewANSIMySQLDialect() *MySQLDialect {
	return &MySQLDialect{ansiMode: true}
}
