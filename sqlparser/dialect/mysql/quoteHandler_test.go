package mysql

import (
	"github.com/cossacklabs/acra/sqlparser/dialect"
	"testing"
)

func TestNewANSIQuoteHandler(t *testing.T) {
	if !NewANSIQuoteHandler().IsModeANSIOn() {
		t.Fatal("ansi mode OFF, must be ON")
	}
}

func TestQuoteHandler_GetIdentifierQuote(t *testing.T) {
	tests := []struct {
		handler       dialect.QuoteHandler
		expectedQuote byte
	}{
		{
			handler:       NewANSIQuoteHandler(),
			expectedQuote: ansiIdentifierQuote,
		},
		{
			handler:       NewDefaultQuoteHandler(),
			expectedQuote: mysqlIdentifierQuote,
		},
	}
	for i, test := range tests {
		t.Run("test expected quotes for identifiers", func(t *testing.T) {
			result := test.handler.GetIdentifierQuote()
			if result != test.expectedQuote {
				t.Fatalf("[%d] incorrect quote from handler %T with ansi mode <%t> for identifiers, took: %s, want %s",
					i, test.handler, test.handler.(*QuoteHandler).IsModeANSIOn(), string(result), string(test.expectedQuote))
			}
		})
	}
}

func TestQuoteHandler_GetStringLiteralQuote(t *testing.T) {
	tests := []struct {
		handler       dialect.QuoteHandler
		expectedQuote byte
	}{
		{
			handler:       NewANSIQuoteHandler(),
			expectedQuote: stringQuote,
		},
		{
			handler:       NewDefaultQuoteHandler(),
			expectedQuote: stringQuote,
		},
	}
	for i, test := range tests {
		t.Run("test expected quotes for string literals", func(t *testing.T) {
			result := test.handler.GetStringLiteralQuote()
			if result != test.expectedQuote {
				t.Fatalf("[%d] incorrect quote from handler %T with ansi mode <%t> for string literals, took: %s, want %s",
					i, test.handler, test.handler.(*QuoteHandler).IsModeANSIOn(), string(result), string(test.expectedQuote))
			}
		})
	}
}

func TestQuoteHandler_IsIdentifierQuote(t *testing.T) {
	type testcase struct {
		handler dialect.QuoteHandler
		quote   byte
		result  bool
	}
	tests := []testcase{
		{
			handler: NewANSIQuoteHandler(),
			quote:   ansiIdentifierQuote,
			result:  true,
		},
		{
			handler: NewANSIQuoteHandler(),
			quote:   mysqlIdentifierQuote,
			result:  true,
		},
		{
			handler: NewDefaultQuoteHandler(),
			quote:   ansiIdentifierQuote,
			result:  false,
		},
		{
			handler: NewDefaultQuoteHandler(),
			quote:   mysqlIdentifierQuote,
			result:  true,
		},
	}
	invalidQuoteValues := []byte{
		'\'',     //string literal
		0,        // non-printable char
		'q',      // printable invalid char
		'[', ']', // quotes acceptable by MS SQL
	}
	handlers := []dialect.QuoteHandler{NewDefaultQuoteHandler(), NewANSIQuoteHandler()}
	// add testcases for each handler for each invalid quote
	for _, handler := range handlers {
		for _, invalidQuote := range invalidQuoteValues {
			tests = append(tests, testcase{handler, invalidQuote, false})
		}
	}

	for _, test := range tests {
		t.Run("test checks for identifier quotes", func(t *testing.T) {
			if test.handler.IsIdentifierQuote(test.quote) != test.result {
				t.Fatalf("handler %v return %t for IsIdentifier('%s') but must return %t",
					test.handler, !test.result, string(test.quote), test.result)
			}
		})
	}
}

func TestQuoteHandler_IsStringLiteralQuote(t *testing.T) {
	type testcase struct {
		handler dialect.QuoteHandler
		quote   byte
		result  bool
	}
	tests := []testcase{
		{
			handler: NewANSIQuoteHandler(),
			quote:   ansiIdentifierQuote,
			result:  false,
		},
		{
			handler: NewANSIQuoteHandler(),
			quote:   stringQuote,
			result:  true,
		},
		{
			handler: NewDefaultQuoteHandler(),
			quote:   ansiIdentifierQuote,
			result:  true,
		},
		{
			handler: NewDefaultQuoteHandler(),
			quote:   stringQuote,
			result:  true,
		},
	}
	invalidQuoteValues := []byte{
		0,        // non-printable char
		'q',      // printable invalid char
		'[', ']', // quotes acceptable by MS SQL
	}
	handlers := []dialect.QuoteHandler{NewDefaultQuoteHandler(), NewANSIQuoteHandler()}
	// add testcases for each handler for each invalid quote
	for _, handler := range handlers {
		for _, invalidQuote := range invalidQuoteValues {
			tests = append(tests, testcase{handler, invalidQuote, false})
		}
	}

	for _, test := range tests {
		t.Run("test checks for string literal quotes", func(t *testing.T) {
			if test.handler.IsStringLiteralQuote(test.quote) != test.result {
				t.Fatalf("handler %v return %t for IsIdentifier('%s') but must return %t",
					test.handler, !test.result, string(test.quote), test.result)
			}
		})
	}
}

func TestQuoteHandler_WrapIdentifier(t *testing.T) {
	testIdentifier := "some identifier"
	tests := []struct {
		handler  dialect.QuoteHandler
		expected string
	}{
		{
			handler:  NewANSIQuoteHandler(),
			expected: string(ansiIdentifierQuote) + testIdentifier + string(ansiIdentifierQuote),
		},
		{
			handler:  NewDefaultQuoteHandler(),
			expected: string(mysqlIdentifierQuote) + testIdentifier + string(mysqlIdentifierQuote),
		},
	}
	for _, test := range tests {
		t.Run("test wrapping identifiers with quotes", func(t *testing.T) {
			result := test.handler.WrapIdentifier(testIdentifier)
			if result != test.expected {
				t.Fatalf("handler wrapped identifier as %s, want: %s", result, test.expected)
			}
		})
	}
}

func TestQuoteHandler_WrapStringLiteral(t *testing.T) {
	testLiteralValue := "some identifier"
	tests := []struct {
		handler  dialect.QuoteHandler
		expected string
	}{
		{
			handler:  NewANSIQuoteHandler(),
			expected: string(stringQuote) + testLiteralValue + string(stringQuote),
		},
		{
			handler:  NewDefaultQuoteHandler(),
			expected: string(stringQuote) + testLiteralValue + string(stringQuote),
		},
	}
	for _, test := range tests {
		t.Run("test wrapping string literals with quotes", func(t *testing.T) {
			result := test.handler.WrapStringLiteral(testLiteralValue)
			if result != test.expected {
				t.Fatalf("handler wrapped string literal as <%s>, want: %s", result, test.expected)
			}
		})
	}
}
