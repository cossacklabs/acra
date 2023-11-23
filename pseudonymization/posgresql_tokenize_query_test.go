package pseudonymization

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"testing"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/sqlparser"
)

// TestMySQLSearchableTokenizationWithTextFormat process searchable SELECT query with placeholder for prepared statement
// and use binding values in text format
func TestPostgreSQLSearchableTokenizationWithTextFormat(t *testing.T) {
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
		Value     []byte
		Type      common.TokenType
		TokenType string
		Query     string
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
		{Value: []byte("9223372036854775807"), Type: common.TokenType_Int64, TokenType: "int64", Query: "UPDATE test_table SET kind = 'Dramatic' WHERE data1=9223372036854775807 and data_ignored='ignoreddata';"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "DELETE FROM test_table WHERE data1='somedata';"},
		{Value: randomBytes, Type: common.TokenType_Bytes, TokenType: "bytes", Query: fmt.Sprintf("DELETE FROM test_table where data1='%s' or data_ignored='ignoreddata'", postgresql.PgEncodeToHexString(randomBytes))},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "select data1 from test_table where data1='somedata'"},
		{Value: []byte("somedata"), Type: common.TokenType_String, TokenType: "str", Query: "select data1 from test_table where data1='somedata' and data_ignored='ignoreddata'"},
		{Value: []byte("333"), Type: common.TokenType_Int32, TokenType: "int32", Query: "select data1 from test_table where data1=333"},
		{Value: []byte("33333333333333333"), Type: common.TokenType_Int64, TokenType: "int64", Query: "select data1 from test_table where data1=33333333333333333"},
		{Value: []byte("test@gmail.com"), Type: common.TokenType_Email, TokenType: "email", Query: "select data1 from test_table where data1='test@gmail.com'"},
		{Value: randomBytes, Type: common.TokenType_Bytes, TokenType: "bytes", Query: fmt.Sprintf("select data1 from test_table where data1='%s'", postgresql.PgEncodeToHexString(randomBytes))},
	}

	for i, tcase := range testcases {
		schema, err := config.MapTableSchemaStoreFromConfig([]byte(fmt.Sprintf(schemaConfigTemplate, tcase.TokenType, tcase.TokenType, tcase.TokenType)), config.UsePostgreSQL)
		assert.NoError(t, err)
		var encryptor = NewPostgresqlTokenizeQuery(schema, tokenEncryptor)

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

		parseResult, err := pg_query.Parse(newQuery.Query())
		assert.NoError(t, err)

		whereExps, err := postgresql.GetWhereStatements(parseResult)
		assert.NoError(t, err)

		var lRightExpr = whereExps[0].GetAExpr().Rexpr.GetAConst()
		if len(whereExps) == 2 {
			if rRightExpr := whereExps[1].GetAExpr().Rexpr.GetAConst(); rRightExpr != nil {
				assert.Equal(t, rRightExpr.GetSval().GetSval(), "ignoreddata")
			}
		}

		if tcase.Type == common.TokenType_Bytes {
			var binAnonymized = anonymized
			if bytes.HasPrefix([]byte(lRightExpr.GetSval().GetSval()), []byte{'\\', 'x'}) {
				binAnonymized = postgresql.PgEncodeToHexString(anonymized)
			}

			assert.Equal(t, []byte(lRightExpr.GetSval().GetSval()), binAnonymized, fmt.Sprintf("Iteration %d", i))
			continue
		}

		switch {
		case lRightExpr.GetSval() != nil:
			assert.Equal(t, []byte(lRightExpr.GetSval().GetSval()), anonymized)
		case lRightExpr.GetIval() != nil:
			assert.Equal(t, []byte(strconv.Itoa(int(lRightExpr.GetIval().GetIval()))), anonymized)
		case lRightExpr.GetFval() != nil:
			assert.Equal(t, []byte(lRightExpr.GetFval().GetFval()), anonymized)
		}
	}
}

func TestPostgreSQLSearchableTokenizationWithDefaultTablesTextFormat(t *testing.T) {
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

		parseResult, err := pg_query.Parse(newQuery.Query())
		assert.NoError(t, err)

		whereExps, err := postgresql.GetWhereStatements(parseResult)
		assert.NoError(t, err)

		for _, whereExp := range whereExps {
			if whereExp == nil {
				panic("nil where expression")
			}

			aExpr := whereExp.GetAExpr()
			if aExpr == nil {
				panic("expected not nil AExpr")
			}

			assert.Equal(t, []byte(aExpr.Rexpr.GetAConst().GetSval().GetSval()), anonymized)
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
		return postgresql.PgEncodeToHexString(anonymized.([]byte)), nil
	}

	return anonymized, nil
}

func TestPostgreSQLEncodingTokenizationWithTextFormatWithCustomTokenizer(t *testing.T) {
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
		{shouldHaveHexEncoding: true, Value: randomBytes, TokenType: "bytes", Query: fmt.Sprintf("INSERT INTO table2 SELECT * FROM test_table WHERE data1='%s';", postgresql.PgEncodeToHexString(randomBytes))},
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

		parseResult, err := pg_query.Parse(newQuery.Query())
		assert.NoError(t, err)

		whereExps, err := postgresql.GetWhereStatements(parseResult)
		assert.NoError(t, err)

		rightExpr := whereExps[0].GetAExpr().Rexpr.GetAConst().GetSval().GetSval()

		consistentTokenization := true
		setting := config.BasicColumnEncryptionSetting{
			TokenType:              tcase.TokenType,
			ConsistentTokenization: &consistentTokenization,
		}

		anonymized, err := tokenizer.Tokenize(tcase.Value, common.TokenContext{ClientID: clientID}, &setting)
		assert.NoError(t, err)

		expectedValue := anonymized
		if tcase.shouldHaveHexEncoding {
			expectedValue = postgresql.PgEncodeToHexString(anonymized)
		}

		assert.Equal(t, []byte(rightExpr), expectedValue, fmt.Sprintf("Fail in %d iteration\n", i))
	}
}
