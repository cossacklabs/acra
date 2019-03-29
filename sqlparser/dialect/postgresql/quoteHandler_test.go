package postgresql

import (
	"testing"
)

func TestNewQuoteHandler(t *testing.T) {
	if NewQuoteHandler() == nil {
		t.Fatal("incorrect creation of quote handler")
	}
}

func TestQuoteHandler_GetIdentifierQuote(t *testing.T) {
	if NewQuoteHandler().GetIdentifierQuote() != ansiIdentifierQuote {
		t.Fatal("invalid quote identifier")
	}
}

func TestQuoteHandler_GetStringLiteralQuote(t *testing.T) {
	if NewQuoteHandler().GetStringLiteralQuote() != stringQuote {
		t.Fatal("incorrect string literal quote")
	}
}

func TestQuoteHandler_IsIdentifierQuote(t *testing.T) {
	handler := NewQuoteHandler()
	type testcase struct {
		quote  byte
		result bool
	}
	tests := []testcase{
		{
			quote:  ansiIdentifierQuote,
			result: true,
		},
	}
	invalidQuoteValues := []byte{
		stringQuote, //string literal
		0,           // non-printable char
		'q',         // printable invalid char
		'[', ']',    // quotes acceptable by MS SQL
	}
	// add testcases for each invalid quote

	for _, invalidQuote := range invalidQuoteValues {
		tests = append(tests, testcase{invalidQuote, false})
	}

	for _, test := range tests {
		t.Run("test checks for identifier quotes", func(t *testing.T) {
			if handler.IsIdentifierQuote(test.quote) != test.result {
				t.Fatalf("handler %v return %t for IsIdentifier('%s') but must return %t",
					handler, !test.result, string(test.quote), test.result)
			}
		})
	}
}

func TestQuoteHandler_IsStringLiteralQuote(t *testing.T) {
	handler := NewQuoteHandler()
	type testcase struct {
		quote  byte
		result bool
	}
	tests := []testcase{
		{
			quote:  stringQuote,
			result: true,
		},
		{
			quote:  ansiIdentifierQuote,
			result: false,
		},
		{
			quote:  0, // non-printable char
			result: false,
		},
		{
			quote:  'q', // printable invalid char
			result: false,
		},
		// quotes acceptable by MS SQL
		{
			quote:  '[',
			result: false,
		},
		{
			quote:  ']',
			result: false,
		},
	}

	for _, test := range tests {
		t.Run("test checks for string literal quotes", func(t *testing.T) {
			if handler.IsStringLiteralQuote(test.quote) != test.result {
				t.Fatalf("handler %v return %t for IsIdentifier('%s') but must return %t",
					handler, !test.result, string(test.quote), test.result)
			}
		})
	}
}

func TestQuoteHandler_WrapIdentifier(t *testing.T) {
	testIdentifier := "some identifier"
	handler := NewQuoteHandler()
	tests := []struct {
		expected string
	}{
		{
			expected: string(ansiIdentifierQuote) + testIdentifier + string(ansiIdentifierQuote),
		},
	}
	for _, test := range tests {
		t.Run("test wrapping identifiers with quotes", func(t *testing.T) {
			result := handler.WrapIdentifier(testIdentifier)
			if result != test.expected {
				t.Fatalf("handler wrapped identifier as %s, want: %s", result, test.expected)
			}
		})
	}
}

func TestQuoteHandler_WrapStringLiteral(t *testing.T) {
	testLiteralValue := "some identifier"
	handler := NewQuoteHandler()
	tests := []struct {
		expected string
	}{
		{
			expected: string(stringQuote) + testLiteralValue + string(stringQuote),
		},
	}
	for _, test := range tests {
		t.Run("test wrapping string literals with quotes", func(t *testing.T) {
			result := handler.WrapStringLiteral(testLiteralValue)
			if result != test.expected {
				t.Fatalf("handler wrapped string literal as <%s>, want: %s", result, test.expected)
			}
		})
	}
}
