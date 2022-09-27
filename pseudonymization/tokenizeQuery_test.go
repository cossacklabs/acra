package pseudonymization

import (
	"context"
	"fmt"
	"testing"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	encryptor2 "github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestSearchableTokenizationWithTextFormat process searchable SELECT query with placeholder for prepared statement
// and use binding values in text format
func TestSearchableTokenizationWithTextFormat(t *testing.T) {
	schemaConfigTemplate := `
schemas:
  - table: test_table
    columns:
      - data1
      - data2
    encrypted:
      - column: data1
        token_type: %s
        consistent_tokenization: true
`
	tokenStorage, err := storage.NewMemoryTokenStorage()
	assert.NoError(t, err)

	anonymizer, err := NewPseudoanonymizer(tokenStorage)
	assert.NoError(t, err)

	tokenizer, err := NewDataTokenizer(anonymizer)
	assert.NoError(t, err)

	tokenEncryptor, err := NewTokenEncryptor(tokenizer)
	assert.NoError(t, err)

	clientSession := &mocks.ClientSession{}
	sessionData := make(map[string]interface{}, 2)
	clientSession.On("GetData", mock.Anything).Return(func(key string) interface{} {
		return sessionData[key]
	}, func(key string) bool {
		_, ok := sessionData[key]
		return ok
	})
	clientSession.On("DeleteData", mock.Anything).Run(func(args mock.Arguments) {
		delete(sessionData, args[0].(string))
	})
	clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		sessionData[args[0].(string)] = args[1]
	})

	clientID := []byte("client-id")
	ctx := base.SetClientSessionToContext(context.Background(), clientSession)

	accessContext := base.NewAccessContext(base.WithClientID(clientID))
	ctx = base.SetAccessContextToContext(ctx, accessContext)

	parser := sqlparser.New(sqlparser.ModeDefault)

	randomBytes := make([]byte, 10)
	randomRead(randomBytes)

	type testcase struct {
		Value     []byte
		Type      common.TokenType
		TokenType string
		Query     string
	}
	testcases := []testcase{
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1='somedata';"},
		{Value: []byte("test@gmail.com"), Type: common.TokenType_Email, TokenType: "email", Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1='test@gmail.com' and data2='ignoreddata';"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "UPDATE test_table SET kind = 'Dramatic' WHERE data1='somedata';"},
		{Value: []byte("4444"), Type: common.TokenType_Int32, TokenType: "int32", Query: "UPDATE test_table SET kind = 'Dramatic' WHERE data1=4444 and data2='ignoreddata';"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "DELETE FROM test_table WHERE data1='somedata';"},
		{Value: randomBytes, Type: common.TokenType_Bytes, TokenType: "bytes", Query: fmt.Sprintf("DELETE FROM test_table where data1='%s' or data2='ignoreddata'", encryptor2.PgEncodeToHexString(randomBytes))},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "select data1 from test_table where data1='somedata'"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "select data1 from test_table where data1='somedata' and data2='ignoreddata'"},
		{Value: []byte("333"), Type: common.TokenType_Int32, TokenType: "int32", Query: "select data1 from test_table where data1=333"},
		{Value: []byte("33333333333333333"), Type: common.TokenType_Int64, TokenType: "int64", Query: "select data1 from test_table where data1=33333333333333333"},
		{Value: []byte("test@gmail.com"), Type: common.TokenType_Email, TokenType: "email", Query: "select data1 from test_table where data1='test@gmail.com'"},
		{Value: randomBytes, Type: common.TokenType_Bytes, TokenType: "bytes", Query: fmt.Sprintf("select data1 from test_table where data1='%s'", encryptor2.PgEncodeToHexString(randomBytes))},
	}

	for _, tcase := range testcases {
		schema, err := config.MapTableSchemaStoreFromConfig([]byte(fmt.Sprintf(schemaConfigTemplate, tcase.TokenType)))
		assert.NoError(t, err)

		encryptor := NewPostgresqlTokenizeQuery(schema, tokenEncryptor)

		setting := config.BasicColumnEncryptionSetting{
			TokenType:              tcase.TokenType,
			ConsistentTokenization: true,
		}
		anonymized, err := tokenizer.Tokenize(tcase.Value, common.TokenContext{ClientID: clientID}, &setting)
		assert.NoError(t, err)

		newQuery, ok, err := encryptor.OnQuery(ctx, base.NewOnQueryObjectFromQuery(tcase.Query, parser))
		assert.NoError(t, err)
		assert.True(t, ok)

		stmt, err := newQuery.Statement()
		assert.NoError(t, err)

		var whereExp *sqlparser.Where
		switch query := stmt.(type) {
		case *sqlparser.Select:
			whereExp = query.Where
		case *sqlparser.Update:
			whereExp = query.Where
		case *sqlparser.Delete:
			whereExp = query.Where
		case *sqlparser.Insert:
			selectInInsert, ok := query.Rows.(*sqlparser.Select)
			if !ok {
				panic("expect INSERT FROM SELECT queries")
			}
			whereExp = selectInInsert.Where
		}

		var rightExpr *sqlparser.SQLVal
		switch expr := whereExp.Expr.(type) {
		case *sqlparser.ComparisonExpr:
			rightExpr = expr.Right.(*sqlparser.SQLVal)
		case *sqlparser.AndExpr:
			rightExpr = expr.Left.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal)
			assert.Equal(t, expr.Right.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal).Val, []byte("ignoreddata"))
		case *sqlparser.OrExpr:
			rightExpr = expr.Left.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal)
			assert.Equal(t, expr.Right.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal).Val, []byte("ignoreddata"))
		}

		if tcase.Type == common.TokenType_Bytes {
			assert.Equal(t, rightExpr.Val, encryptor2.PgEncodeToHexString(anonymized))
			continue
		}

		assert.Equal(t, rightExpr.Val, anonymized)
	}
}
