package sqlparser

import (
	"testing"
)

func TestRedactSQLStatements(t *testing.T) {
	sql := "select a,b,c from t where x = 1234 and y = 1234 and z = 'apple'"
	redactedSQL, err := RedactSQLQuery(sql)
	if err != nil {
		t.Fatalf("redacting sql failed: %v", err)
	}

	if redactedSQL != "select a, b, c from t where x = :replaced1 and y = :replaced1 and z = :replaced2" {
		t.Fatalf("Unknown sql redaction: %v", redactedSQL)
	}
}
