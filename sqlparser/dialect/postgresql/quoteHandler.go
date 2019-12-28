package postgresql

// QuoteHandler for postgresql which uses ANSI version of quotes for identifiers and string literals with some extensions
type QuoteHandler struct{}

const ansiIdentifierQuote = '"'
const stringQuote = '\''

// NewQuoteHandler return new handler
func NewQuoteHandler() *QuoteHandler {
	return &QuoteHandler{}
}

// IsIdentifierQuote return true if quote is correct quote for identifiers
func (handler *QuoteHandler) IsIdentifierQuote(quote byte) bool {
	if quote == ansiIdentifierQuote {
		return true
	}
	return false
}

// IsStringLiteralQuote return true if quote is correct quote for string literal
func (handler *QuoteHandler) IsStringLiteralQuote(quote byte) bool {
	if quote == stringQuote {
		return true
	}
	return false
}

// WrapStringLiteral wrap literal with correct quotes
func (*QuoteHandler) WrapStringLiteral(literal string) string {
	return string(stringQuote) + literal + string(stringQuote)
}

// WrapIdentifier wrap identifier with correct quotes
func (*QuoteHandler) WrapIdentifier(identifier string) string {
	return string(ansiIdentifierQuote) + identifier + string(ansiIdentifierQuote)
}

// GetIdentifierQuote return correct quote for identifier
func (*QuoteHandler) GetIdentifierQuote() byte {
	return ansiIdentifierQuote
}

// GetStringLiteralQuote return correct quote for string literal
func (*QuoteHandler) GetStringLiteralQuote() byte {
	return stringQuote
}
