package decryptor

import (
	"context"
	"testing"

	pg_query "github.com/cossacklabs/pg_query_go/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cossacklabs/acra/crypto"
	decryptor "github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	mocks2 "github.com/cossacklabs/acra/keystore/mocks"
)

// TestSearchableGroupByRewrite verifies that GROUP BY / ORDER BY on a searchable column is rewritten
// to operate on the deterministic HMAC prefix (substr(col, 1, 33)) and that bare references to the
// grouped column are wrapped in an aggregate ((array_agg(col))[1]) to satisfy PostgreSQL's aggregate-or-group-by rule.
// Regression for cossacklabs/acra#729 (PostgreSQL).
func TestSearchableGroupByRewrite(t *testing.T) {
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

	// data1 is searchable, data2 is plaintext.
	schemaConfig := `schemas:
  - table: test_table
    columns:
      - data1
      - data2
    encrypted:
      - column: data1
        searchable: true`
	schema, err := config.MapTableSchemaStoreFromConfig([]byte(schemaConfig), config.UsePostgreSQL)
	assert.NoError(t, err)

	ctx := decryptor.SetClientSessionToContext(context.Background(), clientSession)
	keyStore := &mocks2.ServerKeyStore{}
	keyStore.On("GetHMACSecretKey", mock.Anything).Return([]byte(`some key`), nil)
	registryHandler := crypto.NewRegistryHandler(nil)
	encryptor := NewHashQuery(keyStore, schema, registryHandler)

	selectOf := func(obj postgresql.OnQueryObject) *pg_query.SelectStmt {
		pr, err := obj.Statement()
		assert.NoError(t, err)
		return pr.Stmts[0].Stmt.GetSelectStmt()
	}
	funcNameOf := func(n *pg_query.Node) string {
		// unwrap (array_agg(col))[1] -> array_agg(col)
		if ind := n.GetAIndirection(); ind != nil {
			n = ind.GetArg()
		}
		fc := n.GetFuncCall()
		if fc == nil || len(fc.GetFuncname()) == 0 {
			return ""
		}
		names := fc.GetFuncname()
		return names[len(names)-1].GetString_().GetSval()
	}

	t.Run("GROUP BY searchable rewrites to substr and wraps projection in array_agg", func(t *testing.T) {
		obj := postgresql.NewOnQueryObjectFromQuery("SELECT data1, count(*) FROM test_table GROUP BY data1")
		obj, changed, err := encryptor.OnQuery(ctx, obj)
		assert.NoError(t, err)
		assert.True(t, changed)
		sel := selectOf(obj)
		assert.Equal(t, "substr", funcNameOf(sel.GetGroupClause()[0]))
		rt := sel.GetTargetList()[0].GetResTarget()
		assert.Equal(t, "array_agg", funcNameOf(rt.GetVal()))
		assert.Equal(t, "data1", rt.GetName(), "client-visible column name must be preserved")
	})

	t.Run("ORDER BY searchable wrapped in aggregate", func(t *testing.T) {
		obj := postgresql.NewOnQueryObjectFromQuery("SELECT data1, sum(data2) FROM test_table GROUP BY data1 ORDER BY data1")
		obj, changed, err := encryptor.OnQuery(ctx, obj)
		assert.NoError(t, err)
		assert.True(t, changed)
		sel := selectOf(obj)
		assert.Equal(t, "substr", funcNameOf(sel.GetGroupClause()[0]))
		assert.Equal(t, "array_agg", funcNameOf(sel.GetSortClause()[0].GetSortBy().GetNode()))
	})

	t.Run("WHERE and GROUP BY on searchable both rewritten", func(t *testing.T) {
		obj := postgresql.NewOnQueryObjectFromQuery("SELECT data1, count(*) FROM test_table WHERE data1 = 'x' GROUP BY data1")
		obj, changed, err := encryptor.OnQuery(ctx, obj)
		assert.NoError(t, err)
		assert.True(t, changed)
		sel := selectOf(obj)
		assert.Equal(t, "substr", funcNameOf(sel.GetGroupClause()[0]))
	})

	t.Run("GROUP BY on non-searchable column is left unchanged", func(t *testing.T) {
		obj := postgresql.NewOnQueryObjectFromQuery("SELECT data2, count(*) FROM test_table GROUP BY data2")
		_, changed, err := encryptor.OnQuery(ctx, obj)
		assert.NoError(t, err)
		assert.False(t, changed)
	})

	t.Run("query without GROUP BY is left unchanged", func(t *testing.T) {
		obj := postgresql.NewOnQueryObjectFromQuery("SELECT data1 FROM test_table")
		_, changed, err := encryptor.OnQuery(ctx, obj)
		assert.NoError(t, err)
		assert.False(t, changed)
	})
}
