package dialect

// QuoteHandler decide what the type of quote and manage correct wrapping identifiers and string literals
type QuoteHandler interface {
	IsIdentifierQuote(quote byte) bool
	IsStringLiteralQuote(quote byte) bool
	WrapStringLiteral(literal string) string
	WrapIdentifier(identifier string) string
	GetIdentifierQuote() byte
	GetStringLiteralQuote() byte
}

// Dialect type for Tokenizer
type Dialect interface {
	QuoteHandler() QuoteHandler
}
