package mysql

// QuoteHandler handler to handle quotes for MySQL according to modes
// https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html#sqlmode_ansi_quotes
// https://dev.mysql.com/doc/refman/8.0/en/identifiers.html
type QuoteHandler struct {
	ansiQuotes bool
}

const mysqlIdentifierQuote = '`'
const ansiIdentifierQuote = '"'
const stringQuote = '\''

// NewDefaultQuoteHandler return handler with default setting where ANSI mode = false
func NewDefaultQuoteHandler() *QuoteHandler {
	return &QuoteHandler{ansiQuotes: false}
}

// NewANSIQuoteHandler return handler with ANSI mode = true
func NewANSIQuoteHandler() *QuoteHandler {
	return &QuoteHandler{ansiQuotes: true}
}

// IsModeANSIOn return true if turned on ANSI quotes mode
func (handler *QuoteHandler) IsModeANSIOn() bool {
	return handler.ansiQuotes
}

// IsIdentifierQuote return true if quote is correct quote for identifiers
func (handler *QuoteHandler) IsIdentifierQuote(quote byte) bool {
	if quote == mysqlIdentifierQuote {
		return true
	}
	if handler.ansiQuotes && quote == ansiIdentifierQuote {
		return true
	}
	return false
}

// IsStringLiteralQuote return true if quote is correct quote for string literal
func (handler *QuoteHandler) IsStringLiteralQuote(quote byte) bool {
	if quote == stringQuote {
		return true
	}
	if quote == ansiIdentifierQuote && !handler.ansiQuotes {
		return true
	}
	return false
}

// WrapStringLiteral wrap literal with correct quotes
func (*QuoteHandler) WrapStringLiteral(literal string) string {
	return string(stringQuote) + literal + string(stringQuote)
}

// WrapIdentifier wrap identifier with correct quotes
func (handler *QuoteHandler) WrapIdentifier(identifier string) string {
	if handler.ansiQuotes {
		return string(ansiIdentifierQuote) + identifier + string(ansiIdentifierQuote)
	}
	return string(mysqlIdentifierQuote) + identifier + string(mysqlIdentifierQuote)
}

// GetIdentifierQuote return correct quote for identifier
func (handler *QuoteHandler) GetIdentifierQuote() byte {
	if handler.ansiQuotes {
		return ansiIdentifierQuote
	}
	return mysqlIdentifierQuote
}

// GetStringLiteralQuote return correct quote for string literal
func (*QuoteHandler) GetStringLiteralQuote() byte {
	return stringQuote
}
