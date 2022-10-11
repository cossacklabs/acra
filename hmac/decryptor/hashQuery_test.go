package decryptor

import (
	"context"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
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
    encrypted:
      - column: data1
        searchable: true`

	query := `select data1 from test_table where data1=$1`

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

	queryObj := base.NewOnQueryObjectFromQuery(query, parser)
	queryObj, _, err = encryptor.OnQuery(ctx, queryObj)
	if err != nil {
		t.Fatal(err)
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
