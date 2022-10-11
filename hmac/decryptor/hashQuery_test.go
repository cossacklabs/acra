package decryptor

import (
	"bytes"
	"context"
	"fmt"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	encryptor2 "github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	mocks2 "github.com/cossacklabs/acra/keystore/mocks"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
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

	schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig))
	if err != nil {
		t.Fatal(err)
	}
	ctx := base.SetClientSessionToContext(context.Background(), clientSession)
	parser := sqlparser.New(sqlparser.ModeDefault)
	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)
	encryptor := NewPostgresqlHashQuery(keyStore, schema, registryHandler)
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
		{Query: "SELECT data1 from test_table WHERE data1=$1"},
		{Query: "UPDATE test_table SET kind = 'kind' WHERE data1=$1"},
		{Query: "INSERT INTO table2 SELECT * FROM test_table WHERE data1=$1 and data2=$2"},
		{Query: "DELETE FROM test_table WHERE data1=$1"},
		{Query: "DELETE FROM test_table WHERE data1=$1 OR data2=$2"},
	}
	for _, testcase := range testcases {
		queryObj := base.NewOnQueryObjectFromQuery(testcase.Query, parser)
		queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
		if err != nil {
			t.Fatal(err)
		}
		bindPlaceholders := encryptor2.PlaceholderSettingsFromClientSession(clientSession)
		if len(bindPlaceholders) != 1 {
			t.Fatal("Not found expected amount of placeholders")
		}
		queryObj = base.NewOnQueryObjectFromQuery(testcase.Query, parser)
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

	schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig))
	assert.NoError(t, err)

	ctx := base.SetClientSessionToContext(context.Background(), clientSession)
	parser := sqlparser.New(sqlparser.ModeDefault)
	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)
	encryptor := NewPostgresqlHashQuery(keyStore, schema, registryHandler)
	dataQueryPart := "test-data"

	coder := &encryptor2.PostgresqlDBDataCoder{}

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

		queryObj := base.NewOnQueryObjectFromQuery(query, parser)
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

		_, isSubstrExpr := comparisonExpr.Left.(*sqlparser.SubstrExpr)
		assert.True(t, isSubstrExpr)

		rightVal := comparisonExpr.Right.(*sqlparser.SQLVal)
		assert.NotEqual(t, dataQueryPart, string(rightVal.Val))

		hmacValue, err := encryptor.calculateHmac(ctx, []byte(dataQueryPart))
		assert.NoError(t, err)

		newData, err := coder.Encode(rightVal, hmacValue)
		assert.NoError(t, err)
		assert.Equal(t, len(rightVal.Val), len(newData))
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
    encrypted:
      - column: data1
        searchable: true
`

	type testcase struct {
		Query string
	}

	testcases := []testcase{
		{Query: "SELECT * FROM table1 t1 inner join test_table t2 inner join test_table_2 t3 on t2.data1=t3.data1"},
		{Query: "SELECT * FROM table1 t1 inner join test_table_2 t3 on t3.data1='some_data'"},
	}

	for _, tcase := range testcases {
		schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig))
		if err != nil {
			t.Fatal(err)
		}
		ctx := base.SetClientSessionToContext(context.Background(), clientSession)
		parser := sqlparser.New(sqlparser.ModeDefault)
		keyStore := &mocks2.ServerKeyStore{}
		keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
		registryHandler := crypto.NewRegistryHandler(nil)
		encryptor := NewPostgresqlHashQuery(keyStore, schema, registryHandler)

		queryObj := base.NewOnQueryObjectFromQuery(tcase.Query, parser)
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

				switch expr := expr.Right.(type) {
				case *sqlparser.SQLVal:
					// if RightExpr is SQLVal check weather its hash
					assert.True(t, len(expr.Val) == 68)
				case *sqlparser.SubstrExpr:
					assert.Equal(t, sqlparser.String(expr.Name), "t3.data1")
				}
			}
		}
	}
}
