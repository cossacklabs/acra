package pseudonymization

import (
	"bytes"
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

      - column: data2
        token_type: %s
        consistent_tokenization: true

  - table: test_table_test
    columns:
      - row_data1
      - data2
    encrypted:
      - column: row_data1
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
		Value      []byte
		Type       common.TokenType
		TokenType  string
		Query      string
		OnlyDBType *bool
	}
	getBoolReference := func(v bool) *bool {
		return &v
	}

	testcases := []testcase{
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1='somedata';"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "SELECT * FROM table1 t1 inner join test_table t2 on  t2.data1='somedata' and t2.name=t1.name"},
		//just some test some inner join with filter on t2.data1=t1.name to test printing some warning log that searchable encryption can be applied only to value comparison
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "SELECT * FROM table1 t1 inner join test_table t2 on t2.data1='somedata' and t2.data2=t1.name"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "SELECT * FROM table1 t1 inner join test_table t2 on  t2.data1='somedata' inner join test_table_test t3 on  t3.row_data1='somedata' and t3.name=t1.name"},
		{Value: []byte("test@gmail.com"), Type: common.TokenType_Email, TokenType: "email", Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1='test@gmail.com' and data_ignored='ignoreddata';"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "UPDATE test_table SET kind = 'Dramatic' WHERE data1='somedata';"},
		{Value: []byte("4444"), Type: common.TokenType_Int32, TokenType: "int32", Query: "UPDATE test_table SET kind = 'Dramatic' WHERE data1=4444 and data_ignored='ignoreddata';"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "DELETE FROM test_table WHERE data1='somedata';"},
		{Value: randomBytes, Type: common.TokenType_Bytes, TokenType: "bytes", Query: fmt.Sprintf("DELETE FROM test_table where data1='%s' or data_ignored='ignoreddata'", encryptor2.PgEncodeToHexString(randomBytes)), OnlyDBType: getBoolReference(config.UsePostgreSQL)},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "select data1 from test_table where data1='somedata'"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "select data1 from test_table where data1='somedata' and data_ignored='ignoreddata'"},
		{Value: []byte("333"), Type: common.TokenType_Int32, TokenType: "int32", Query: "select data1 from test_table where data1=333"},
		{Value: []byte("33333333333333333"), Type: common.TokenType_Int64, TokenType: "int64", Query: "select data1 from test_table where data1=33333333333333333"},
		{Value: []byte("test@gmail.com"), Type: common.TokenType_Email, TokenType: "email", Query: "select data1 from test_table where data1='test@gmail.com'"},
		{Value: randomBytes, Type: common.TokenType_Bytes, TokenType: "bytes", Query: fmt.Sprintf("select data1 from test_table where data1='%s'", encryptor2.PgEncodeToHexString(randomBytes)), OnlyDBType: getBoolReference(config.UsePostgreSQL)},
	}

	for i, tcase := range testcases {
		for _, dbType := range []bool{config.UseMySQL, config.UsePostgreSQL} {
			// skip tests targeted to another db type
			if tcase.OnlyDBType != nil && *tcase.OnlyDBType != dbType {
				t.Logf("Test case %d only for UseMysql=%t, but now test UseMysql=%t\n", i, *tcase.OnlyDBType, dbType)
				continue
			}
			schema, err := config.MapTableSchemaStoreFromConfig([]byte(fmt.Sprintf(schemaConfigTemplate, tcase.TokenType, tcase.TokenType, tcase.TokenType)), dbType)
			assert.NoError(t, err)
			var encryptor *TokenizeQuery
			switch dbType {
			case config.UseMySQL:
				encryptor = NewMySQLTokenizeQuery(schema, tokenEncryptor)
			case config.UsePostgreSQL:
				encryptor = NewPostgresqlTokenizeQuery(schema, tokenEncryptor)
			default:
				t.Fatal("Unexpected db type")
			}

			consistentTokenization := true
			setting := config.BasicColumnEncryptionSetting{
				TokenType:              tcase.TokenType,
				ConsistentTokenization: &consistentTokenization,
			}
			anonymized, err := tokenizer.Tokenize(tcase.Value, common.TokenContext{ClientID: clientID}, &setting)
			assert.NoError(t, err)

			newQuery, ok, err := encryptor.OnQuery(ctx, base.NewOnQueryObjectFromQuery(tcase.Query, parser))
			assert.NoError(t, err)
			assert.True(t, ok)

			stmt, err := newQuery.Statement()
			assert.NoError(t, err)

			var whereExps = make([]*sqlparser.Where, 0)
			err = sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
				switch nodeType := node.(type) {
				case *sqlparser.Where:
					whereExps = append(whereExps, nodeType)
				case sqlparser.JoinCondition:
					whereExps = append(whereExps, &sqlparser.Where{
						Type: "on",
						Expr: nodeType.On,
					})
				}
				return true, nil
			}, stmt)

			for _, whereExp := range whereExps {
				if whereExp == nil {
					continue
				}

				var lRightExpr *sqlparser.SQLVal
				switch expr := whereExp.Expr.(type) {
				case *sqlparser.ComparisonExpr:
					lRightExpr = expr.Right.(*sqlparser.SQLVal)
				case *sqlparser.AndExpr:
					lRightExpr = expr.Left.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal)

					rRightExpr := expr.Right.(*sqlparser.ComparisonExpr).Right
					if sqlVal, ok := rRightExpr.(*sqlparser.SQLVal); ok {
						assert.Equal(t, sqlVal.Val, []byte("ignoreddata"))
					}

				case *sqlparser.OrExpr:
					lRightExpr = expr.Left.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal)
					assert.Equal(t, expr.Right.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal).Val, []byte("ignoreddata"))
				}

				if tcase.Type == common.TokenType_Bytes {
					var binAnonymized = anonymized
					if bytes.HasPrefix(lRightExpr.Val, []byte{'\\', 'x'}) {
						binAnonymized = encryptor2.PgEncodeToHexString(anonymized)
					}

					assert.Equal(t, lRightExpr.Val, binAnonymized, fmt.Sprintf("Iteration %d", i))
					continue
				}

				assert.Equal(t, lRightExpr.Val, anonymized)
			}
		}
	}
}

func TestSearchableTokenizationWithDefaultTablesTextFormat(t *testing.T) {
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

	schemaConfig := `schemas:
  - table: test_table
    columns:
      - data1
    encrypted:
      - column: data1
        token_type: str
        consistent_tokenization: true
        client_id: client_test_table		

  - table: test_table_2
    columns:
      - data1
    encrypted:
      - column: data1
        token_type: str
        consistent_tokenization: true
        client_id: client_test_table_2		
`
	ctx := base.SetClientSessionToContext(context.Background(), clientSession)
	ctx = base.SetAccessContextToContext(ctx, base.NewAccessContext())

	type testcase struct {
		Query    string
		ClientID []byte
	}

	clientIDTestTable := []byte("client_test_table")
	clientIDTestTable2 := []byte("client_test_table_2")

	dataToTokenize := []byte("some_data")
	testcases := []testcase{
		// check matching with default table test_table_2 present in config, table1 with alias not in config
		{ClientID: clientIDTestTable2, Query: "SELECT * FROM test_table_2 inner join table1 t2 on data1='%s'"},
		// check matching with default table test_table default present in config, test_table_2 in the config too, but hash alias
		{ClientID: clientIDTestTable, Query: "SELECT * FROM test_table inner join test_table_2 t2 on data1='%s'"},
		{ClientID: clientIDTestTable, Query: "SELECT value1 FROM test_table t1, test_table_2 where t1.data1='%s'"},
		{ClientID: clientIDTestTable2, Query: "SELECT value1 FROM test as tt, test_table_2 t2, test_table where t2.data1='%s'"},
	}

	parser := sqlparser.New(sqlparser.ModeDefault)

	for _, tcase := range testcases {
		schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig), config.UseMySQL)
		assert.NoError(t, err)

		encryptor := NewPostgresqlTokenizeQuery(schema, tokenEncryptor)

		consistentTokenization := true
		setting := config.BasicColumnEncryptionSetting{
			TokenType:              "str",
			ConsistentTokenization: &consistentTokenization,
		}
		anonymized, err := tokenizer.Tokenize(dataToTokenize, common.TokenContext{ClientID: tcase.ClientID}, &setting)
		assert.NoError(t, err)

		newQuery, ok, err := encryptor.OnQuery(ctx, base.NewOnQueryObjectFromQuery(fmt.Sprintf(tcase.Query, dataToTokenize), parser))
		assert.NoError(t, err)
		assert.True(t, ok)

		stmt, err := newQuery.Statement()
		assert.NoError(t, err)

		var whereExps = make([]*sqlparser.Where, 0)
		err = sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
			switch nodeType := node.(type) {
			case *sqlparser.Where:
				whereExps = append(whereExps, nodeType)
			case sqlparser.JoinCondition:
				whereExps = append(whereExps, &sqlparser.Where{
					Type: "on",
					Expr: nodeType.On,
				})
			}
			return true, nil
		}, stmt)

		for _, whereExp := range whereExps {
			if whereExp == nil {
				continue
			}
			comparisonExpr, ok := whereExp.Expr.(*sqlparser.ComparisonExpr)
			assert.True(t, ok)

			assert.Equal(t, comparisonExpr.Right.(*sqlparser.SQLVal).Val, anonymized)
		}
	}
}

type customAnonymizer struct {
	common.Pseudoanonymizer
}

func (c customAnonymizer) AnonymizeConsistently(data interface{}, context common.TokenContext, dataType common.TokenType) (interface{}, error) {
	anonymized, err := c.Pseudoanonymizer.AnonymizeConsistently(data, context, dataType)
	if err != nil {
		return nil, err
	}

	if dataType == common.TokenType_Bytes {
		// pretend anonymizer return encoded data that should be encode to hex
		return encryptor2.PgEncodeToHexString(anonymized.([]byte)), nil
	}

	return anonymized, nil
}

func TestEncodingTokenizationWithTextFormatWithCustomTokenizer(t *testing.T) {
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

      - column: data2
        token_type: %s
        consistent_tokenization: true
`

	tokenStorage, err := storage.NewMemoryTokenStorage()
	assert.NoError(t, err)

	anonymizer, err := NewPseudoanonymizer(tokenStorage)
	assert.NoError(t, err)

	customAnonymizer := customAnonymizer{
		anonymizer,
	}

	tokenizer, err := NewDataTokenizer(customAnonymizer)
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
		Value                 []byte
		TokenType             string
		Query                 string
		shouldHaveHexEncoding bool
	}

	testcases := []testcase{
		{Value: []byte("somedata"), TokenType: "str", Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1='somedata';"},
		{shouldHaveHexEncoding: true, Value: randomBytes, TokenType: "bytes", Query: fmt.Sprintf("INSERT INTO table2 SELECT * FROM test_table WHERE data1='%s';", encryptor2.PgEncodeToHexString(randomBytes))},
		{shouldHaveHexEncoding: true, Value: []byte("q{r."), TokenType: "bytes", Query: fmt.Sprintf("INSERT INTO table2 SELECT * FROM test_table WHERE data1='%s';", []byte("q{r."))},
	}

	for i, tcase := range testcases {
		_ = i
		schema, err := config.MapTableSchemaStoreFromConfig([]byte(fmt.Sprintf(schemaConfigTemplate, tcase.TokenType, tcase.TokenType)), config.UsePostgreSQL)
		assert.NoError(t, err)

		encryptor := NewPostgresqlTokenizeQuery(schema, tokenEncryptor)

		newQuery, ok, err := encryptor.OnQuery(ctx, base.NewOnQueryObjectFromQuery(tcase.Query, parser))
		assert.NoError(t, err)
		assert.True(t, ok)

		newStat, err := newQuery.Statement()
		assert.NoError(t, err)

		rightExpr := newStat.(*sqlparser.Insert).Rows.(*sqlparser.Select).Where.Expr.(*sqlparser.ComparisonExpr).Right.(*sqlparser.SQLVal)

		consistentTokenization := true
		setting := config.BasicColumnEncryptionSetting{
			TokenType:              tcase.TokenType,
			ConsistentTokenization: &consistentTokenization,
		}

		anonymized, err := tokenizer.Tokenize(tcase.Value, common.TokenContext{ClientID: clientID}, &setting)
		assert.NoError(t, err)

		expectedValue := anonymized
		if tcase.shouldHaveHexEncoding {
			expectedValue = encryptor2.PgEncodeToHexString(anonymized)
		}

		assert.Equal(t, rightExpr.Val, expectedValue, fmt.Sprintf("Fail in %d iteration\n", i))
	}
}
