package decryptor

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cossacklabs/acra/crypto"
	decryptor "github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	mocks2 "github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/acra/sqlparser"
)

// TestSearchablePreparedStatementsWithTextFormat process searchable SELECT query with placeholder for prepared statement
// and use binding values in text format
func TestSearchablePreparedStatementsWithTextFormat(t *testing.T) {
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
      - data2
    encrypted:
      - column: data1
        searchable: true`

	schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig), config.UseMySQL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := decryptor.SetClientSessionToContext(context.Background(), clientSession)
	parser := sqlparser.New(sqlparser.ModeDefault)
	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)
	encryptor := NewHashQuery(keyStore, schema, registryHandler)
	sourceBindValue := []byte{0, 1, 2, 3}
	boundValue := &mocks.BoundValue{}
	bindValue := sourceBindValue
	boundValue.On("Format").Return(decryptor.TextFormat)
	boundValue.On("GetData", mock.Anything).Return(func(config.ColumnEncryptionSetting) []byte {
		return bindValue
	}, nil)
	boundValue.On("SetData", mock.MatchedBy(func(data []byte) bool {
		bindValue = data
		return true
	}), mock.Anything).Return(nil)
	_ = bindValue

	type testcase struct {
		Query string
	}
	testcases := []testcase{
		{Query: "SELECT data1 from test_table WHERE data1=$1"},
		{Query: "UPDATE test_table SET kind = 'kind' WHERE data1=$1"},
		{Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1=$1 and data2=$2"},
		{Query: "DELETE FROM test_table WHERE data1=$1"},
		{Query: "DELETE FROM test_table WHERE data1=$1 OR data2=$2"},
	}
	for _, testcase := range testcases {
		queryObj := decryptor.NewOnQueryObjectFromQuery(testcase.Query, parser)
		queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
		if err != nil {
			t.Fatal(err)
		}
		bindPlaceholders := base.PlaceholderSettingsFromClientSession(clientSession)
		if len(bindPlaceholders) != 1 {
			t.Fatal("Not found expected amount of placeholders")
		}
		queryObj = decryptor.NewOnQueryObjectFromQuery(testcase.Query, parser)
		statement, err := queryObj.Statement()
		if err != nil {
			t.Fatal(err)
		}
		newVals, ok, err := encryptor.OnBind(ctx, statement, []decryptor.BoundValue{boundValue})
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("Values should be changed")
		}
		if len(newVals) != 1 {
			t.Fatal("Invalid amount of bound values")
		}
		setting := schema.GetTableSchema("test_table").GetColumnEncryptionSettings("data1")
		newData, err := newVals[0].GetData(setting)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(newData, sourceBindValue) {
			t.Fatal("Data wasn't changed")
		}
	}
}

// TestSearchableWithTextFormat process searchable SELECT query without placeholders with text format
func TestSearchableWithTextFormat(t *testing.T) {
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
     - data2
   encrypted:
     - column: data1
       searchable: true`

	schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig), config.UseMySQL)
	assert.NoError(t, err)

	ctx := decryptor.SetClientSessionToContext(context.Background(), clientSession)
	parser := sqlparser.New(sqlparser.ModeDefault)
	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)
	encryptor := NewHashQuery(keyStore, schema, registryHandler)
	dataQueryPart := "test-data"

	coder := &postgresql.PostgresqlPgQueryDBDataCoder{}

	type testcase struct {
		Query string
	}
	testcases := []testcase{
		{Query: "SELECT data1 from test_table WHERE data1='%s'"},
		{Query: "UPDATE test_table SET kind = 'kind' WHERE data1='%s'"},
		{Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1='%s' and data2='other-data'"},
		{Query: "DELETE FROM test_table WHERE data1='%s'"},
		{Query: "DELETE FROM test_table WHERE data1='%s' OR data2='other-data'"},
	}
	for _, testcase := range testcases {
		query := fmt.Sprintf(testcase.Query, dataQueryPart)

		queryObj := decryptor.NewOnQueryObjectFromQuery(query, parser)
		queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
		assert.NoError(t, err)

		parseResult, err := pg_query.Parse(queryObj.Query())
		assert.NoError(t, err)

		whereStatements, err := postgresql.GetWhereStatements(parseResult)
		assert.NoError(t, err)
		assert.True(t, len(whereStatements) > 0)

		var aExpr *pg_query.A_Expr
		if whereStatements[0].GetAExpr() != nil {
			aExpr = whereStatements[0].GetAExpr()
		}
		assert.NotNil(t, aExpr.Lexpr.GetFuncCall())

		aConst := aExpr.Rexpr.GetAConst()
		rightVal := aExpr.Rexpr.GetAConst().GetSval().GetSval()
		assert.NotEqual(t, dataQueryPart, rightVal)

		hmacValue, err := encryptor.calculateHmac(ctx, []byte(dataQueryPart))
		assert.NoError(t, err)

		err = coder.Encode(aConst, hmacValue, &config.BasicColumnEncryptionSetting{})
		assert.NoError(t, err)
		assert.Equal(t, len(rightVal), len(aConst.GetSval().Sval))
	}
}

// TestSearchableWithJoinsWithTextFormat process searchable SELECT query with placeholder for prepared statement
// and use binding values in text format
func TestSearchableWithJoinsWithTextFormat(t *testing.T) {
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
       searchable: true

 - table: test_table_2
   columns:
     - data1
     - data2
   encrypted:
     - column: data1
       searchable: true
     - column: data2
       searchable: true
`

	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)

	schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig), config.UseMySQL)
	if err != nil {
		t.Fatal(err)
	}

	type testcase struct {
		Query string
	}

	testcases := []testcase{
		{Query: "SELECT * FROM table1 t1 inner join test_table t2 on t2.test= t1.test inner join test_table_2 t3 on t2.data1=t3.data1"},
		{Query: "SELECT * FROM table1 inner join test_table on table1.test = test_table.test  inner join test_table_2 on test_table.data1=test_table_2.data1"},
		{Query: "SELECT * FROM table1 inner join test_table t1 on t1.test = table1.test inner join test_table_2 on t1.data1=test_table_2.data1"},
		{Query: "SELECT * FROM test_table as t1 join some_table_1 on some_table_1.test = test_table.test join some_table_2 on some_table_2.test = some_table_1.test join test_table_2 on t1.data1=test_table_2.data1"},
		{Query: "SELECT * FROM table1 t1 inner join test_table_2 t3 on t3.data1='some_data'"},
		{Query: "SELECT * FROM test_table_2 inner join table1 t2 on data2='some_data'"},
		{Query: "SELECT * FROM test_table inner join test_table_2 t2 on data1='some_data'"},
		{Query: "SELECT value1 FROM test_table t1, test_table_2 where t1.data1='some_data'"},
		{Query: "SELECT value1 FROM test as tt, test_table_2 t2, test_table where data2='some_data'"},
	}

	encryptors := []*HashQuery{NewHashQuery(keyStore, schema, registryHandler)}
	for _, encryptor := range encryptors {
		for _, tcase := range testcases {
			ctx := decryptor.SetClientSessionToContext(context.Background(), clientSession)
			parser := sqlparser.New(sqlparser.ModeDefault)

			queryObj := decryptor.NewOnQueryObjectFromQuery(tcase.Query, parser)
			queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
			assert.NoError(t, err)

			parseResult, err := pg_query.Parse(queryObj.Query())
			assert.NoError(t, err)

			whereStatements, err := postgresql.GetWhereStatements(parseResult)
			assert.NoError(t, err)
			assert.True(t, len(whereStatements) > 0)

			for _, whereExp := range whereStatements {
				if whereExp == nil {
					continue
				}

				if expr := whereExp.GetAExpr(); expr != nil {
					if funcCall := expr.Rexpr.GetFuncCall(); funcCall != nil {
						assert.Equal(t, funcCall.GetFuncname()[0].GetString_().GetSval(), postgresql.SubstrFuncName)

						columnName := funcCall.GetArgs()[0].GetColumnRef().GetFields()[0].GetString_().GetSval()
						if len(funcCall.GetArgs()[0].GetColumnRef().GetFields()) == 2 {
							columnName = funcCall.GetArgs()[0].GetColumnRef().GetFields()[1].GetString_().GetSval()
						}
						assert.Equal(t, columnName, "data1")
					}

					if aConst := expr.Rexpr.GetAConst(); aConst != nil {
						assert.True(t, len(aConst.GetSval().GetSval()) == 68, "expect replacing value on substring with hash `%s`", queryObj.Query())
					}
				}
			}
		}
	}
}
