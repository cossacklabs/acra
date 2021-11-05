package sqlparser

import querypb "github.com/cossacklabs/acra/sqlparser/dependency/querypb"

// RedactSQLQuery returns a sql string with the params stripped out for display
func RedactSQLQuery(sql string) (string, error) {
	bv := map[string]*querypb.BindVariable{}
	sqlStripped, comments := SplitMarginComments(sql)

	stmt, err := New(ModeStrict).Parse(sqlStripped)
	if err != nil {
		return "", err
	}

	Normalize(stmt, bv, ValueMask)

	return comments.Leading + String(stmt) + comments.Trailing, nil
}
