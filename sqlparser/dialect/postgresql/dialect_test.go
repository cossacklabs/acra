package postgresql

import "testing"

func TestNewPostgreSQLDialect(t *testing.T) {
	if NewPostgreSQLDialect() == nil {
		t.Fatal("return invalid dialect")
	}
}

func TestPostgreSQLDialect_QuoteHandler(t *testing.T) {
	if NewPostgreSQLDialect().QuoteHandler() == nil {
		t.Fatal("return invalid quote handler")
	}
	if _, ok := NewPostgreSQLDialect().QuoteHandler().(*QuoteHandler); !ok {
		t.Fatal("return invalid type of quote handler")
	}
}
