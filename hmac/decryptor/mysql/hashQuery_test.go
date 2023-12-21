package decryptor

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	encryptor2 "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/mysql"
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
	ctx := base.SetClientSessionToContext(context.Background(), clientSession)
	parser := sqlparser.New(sqlparser.ModeDefault)
	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)
	encryptor := NewHashQuery(keyStore, schema, registryHandler)
	sourceBindValue := []byte{0, 1, 2, 3}
	boundValue := &mocks.BoundValue{}
	bindValue := sourceBindValue
	boundValue.On("Format").Return(base.TextFormat)
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
		{Query: "SELECT data1 from test_table WHERE data1=?"},
		{Query: "UPDATE test_table SET kind = 'kind' WHERE data1=?"},
		{Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1=? and data2=?"},
		{Query: "DELETE FROM test_table WHERE data1=?"},
		{Query: "DELETE FROM test_table WHERE data1=? OR data2=?"},
	}
	for _, testcase := range testcases {
		queryObj := mysql.NewOnQueryObjectFromQuery(testcase.Query, parser)
		queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
		if err != nil {
			t.Fatal(err)
		}
		bindPlaceholders := encryptor2.PlaceholderSettingsFromClientSession(clientSession)
		if len(bindPlaceholders) != 1 {
			t.Fatal("Not found expected amount of placeholders")
		}
		queryObj = mysql.NewOnQueryObjectFromQuery(testcase.Query, parser)
		statement, err := queryObj.Statement()
		if err != nil {
			t.Fatal(err)
		}
		newVals, ok, err := encryptor.OnBind(ctx, statement, []base.BoundValue{boundValue})
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
		{Query: "SELECT * FROM table1 t1 inner join test_table t2 inner join test_table_2 t3 on t2.data1=t3.data1"},
		{Query: "SELECT * FROM table1 inner join test_table inner join test_table_2 on test_table.data1=test_table_2.data1"},
		{Query: "SELECT * FROM table1 inner join test_table t1 inner join test_table_2 on t1.data1=test_table_2.data1"},
		{Query: "SELECT * FROM test_table as t1 join some_table_1 join some_table_2 join test_table_2 on t1.data1=test_table_2.data1"},
		{Query: "SELECT * FROM table1 t1 inner join test_table_2 t3 on t3.data1='some_data'"},
		{Query: "SELECT * FROM test_table_2 inner join table1 t2 on data2='some_data'"},
		{Query: "SELECT * FROM test_table inner join test_table_2 t2 on data1='some_data'"},
		{Query: "SELECT value1 FROM test_table t1, test_table_2 where t1.data1='some_data'"},
		{Query: "SELECT value1 FROM test as tt, test_table_2 t2, test_table where data2='some_data'"},
	}

	encryptors := []*HashQuery{NewHashQuery(keyStore, schema, registryHandler)}
	for _, encryptor := range encryptors {
		for _, tcase := range testcases {
			ctx := base.SetClientSessionToContext(context.Background(), clientSession)
			parser := sqlparser.New(sqlparser.ModeDefault)

			queryObj := mysql.NewOnQueryObjectFromQuery(tcase.Query, parser)
			queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
			assert.NoError(t, err)

			stmt, err := queryObj.Statement()
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

				switch expr := whereExp.Expr.(type) {
				case *sqlparser.ComparisonExpr:

					if whereExp.Type == sqlparser.WhereStr {
						convertExpr, ok := expr.Left.(*sqlparser.ConvertExpr)
						assert.True(t, ok)

						_, ok = convertExpr.Expr.(*sqlparser.SubstrExpr)
						assert.True(t, ok)
					}

					switch expr := expr.Right.(type) {
					case *sqlparser.SQLVal:
						// if RightExpr is SQLVal check weather its hash
						assert.True(t, len(expr.Val) == 68, "expect replacing value on substring with hash `%s`", queryObj.Query())
					case *sqlparser.SubstrExpr:
						assert.Equal(t, sqlparser.String(expr.Name.Name), "data1")
					}
				}
			}
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

	ctx := base.SetClientSessionToContext(context.Background(), clientSession)
	parser := sqlparser.New(sqlparser.ModeDefault)
	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)
	encryptor := NewHashQuery(keyStore, schema, registryHandler)
	dataQueryPart := "test-data"

	coder := &mysql.DBDataCoder{}

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

		queryObj := mysql.NewOnQueryObjectFromQuery(query, parser)
		queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
		assert.NoError(t, err)

		stmt, err := queryObj.Statement()
		assert.NoError(t, err)

		var whereStatements []*sqlparser.Where
		err = sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
			where, ok := node.(*sqlparser.Where)
			if ok {
				whereStatements = append(whereStatements, where)
			}
			return true, nil
		}, stmt)
		assert.NoError(t, err)
		assert.True(t, len(whereStatements) > 0)

		var comparisonExpr *sqlparser.ComparisonExpr
		switch node := whereStatements[0].Expr.(type) {
		case *sqlparser.ComparisonExpr:
			comparisonExpr = node
		case *sqlparser.AndExpr:
			comparisonExpr = node.Left.(*sqlparser.ComparisonExpr)
		case *sqlparser.OrExpr:
			comparisonExpr = node.Left.(*sqlparser.ComparisonExpr)
		}
		fmt.Println(sqlparser.String(stmt))

		if exr, isConvert := comparisonExpr.Left.(*sqlparser.ConvertExpr); isConvert {
			_, isSubstrExpr := exr.Expr.(*sqlparser.SubstrExpr)
			assert.True(t, isSubstrExpr)

		} else {
			_, isSubstrExpr := comparisonExpr.Left.(*sqlparser.SubstrExpr)
			assert.True(t, isSubstrExpr)
		}

		rightVal := comparisonExpr.Right.(*sqlparser.SQLVal)
		assert.NotEqual(t, dataQueryPart, string(rightVal.Val))

		hmacValue, err := encryptor.calculateHmac(ctx, []byte(dataQueryPart))
		assert.NoError(t, err)

		newData, err := coder.Encode(rightVal, hmacValue, &config.BasicColumnEncryptionSetting{})
		assert.NoError(t, err)
		assert.Equal(t, len(rightVal.Val), len(newData))
	}
}
