//go:build integration && mysql
// +build integration,mysql

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	"github.com/cossacklabs/acra/decryptor/mysql/types"
	encryptorConfig "github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/pseudonymization"
	common2 "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils/tests"
	acra_server "github.com/cossacklabs/acra/utils/tests/acra-server"
)

func getProxyFactory(t *testing.T, serverConfig *common.Config, tokenizer common2.Pseudoanonymizer) base.ProxyFactory {
	workingDirectory := tests.GetSourceRootDirectory(t)
	tlsConfig, err := network.NewTLSConfig("localhost",
		filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"),
		filepath.Join(workingDirectory, "tests/ssl/acra-server/acra-server.key"),
		filepath.Join(workingDirectory, "tests/ssl/acra-server/acra-server.crt"),
		1, nil)
	assert.Nil(t, err)
	tlsWrapper, err := network.NewTLSAuthenticationConnectionWrapper(
		serverConfig.GetUseClientIDFromCertificate(), tlsConfig, tlsConfig, serverConfig.GetTLSClientIDExtractor())
	assert.Nil(t, err)
	proxyTLSWrapper := base.NewTLSConnectionWrapper(serverConfig.GetUseClientIDFromCertificate(), tlsWrapper)
	sqlParser := sqlparser.New(sqlparser.ModeDefault)
	proxySetting := base.NewProxySetting(sqlParser, serverConfig.GetTableSchema(), serverConfig.GetKeyStore(), proxyTLSWrapper,
		acracensor.NewAcraCensor(), poison.NewCallbackStorage())
	serverProxyFactory, err := NewProxyFactory(proxySetting, serverConfig.GetKeyStore(), tokenizer)
	assert.Nil(t, err)
	return serverProxyFactory
}

func TestTransparentEncryption(t *testing.T) {
	const timeout = time.Millisecond * 400
	freePort := tests.GetFreePortForListener(t)
	serverConfig := acra_server.NewDefaultAcraServerConfig(t)
	clientID := []byte("clientID")
	serverConfig.SetDBConnectionSettings("localhost", 3306)
	serverConfig.SetUseClientIDFromCertificate(false)
	assert := assert.New(t)
	assert.Nil(serverConfig.SetStaticClientID(clientID))
	serverKeystore := serverConfig.GetKeyStore()
	assert.Nil(serverKeystore.GenerateClientIDSymmetricKey(clientID))
	assert.Nil(serverKeystore.GenerateHmacKey(clientID))
	logging.SetLogLevel(logging.LogDebug)

	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeBlob), &types.BlobDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeString), &types.StringDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeLong), &types.LongDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeLongLong), &types.LongLongDataTypeEncoder{})

	schemaConfig := `
schemas:
  - table: customer
    columns:
      - name
      - searchable
      - field_int
      - field_int2
      - point_field	
    encrypted:
      - column: name
        data_type_db_identifier: 254
      - column: searchable
        searchable: true
        data_type_db_identifier: 254
      - column: field_int
        data_type_db_identifier: 3
      - column: field_int2
        data_type_db_identifier: 8
`
	schemaStore, err := encryptorConfig.MapTableSchemaStoreFromConfig([]byte(schemaConfig), true)
	assert.Nil(err)
	serverConfig.SetTableSchema(schemaStore)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(timeout))
	tokenStorage, err := storage.NewMemoryTokenStorage()
	assert.Nil(err)
	tokenizer, err := pseudonymization.NewPseudoanonymizer(tokenStorage)
	assert.Nil(err)
	serverProxyFactory := getProxyFactory(t, serverConfig, tokenizer)
	serverConfig.SetAcraConnectionString("tcp://localhost:" + strconv.Itoa(freePort))
	acraServer := acra_server.NewAcraServer(t, serverConfig, serverProxyFactory)
	go func() {
		acraServer.Start(ctx)
	}()
	defer cancel()
	defer func() {
		acraServer.Close()
	}()

	dbConfig := tests.GetDatabaseConfig(t)
	dbCon := openConnection(dbConfig, dbConfig.Port)
	acraCon := openConnection(dbConfig, freePort)

	var (
		nameArg         = "test_name"
		searchArg       = "search_arg"
		field1Arg       = 12345
		field2Arg int64 = 12345678901
	)
	executeQuery(dbCon, "CREATE TABLE IF NOT EXISTS customer(name blob, searchable blob, field_int blob, field_int2 blob, point_field point);")
	executeQuery(dbCon, "TRUNCATE table customer;")
	executeQuery(acraCon, "insert into customer (name, searchable, field_int, field_int2, point_field) values (?, ?, ?, ?, POINT(25.7786222, -80.1956483));", nameArg, searchArg, field1Arg, field2Arg)

	var (
		nameQueryResult   string
		searchQueryResult string
		field1QueryResult int
		field2QueryResult int64
		pointQueryResult  []byte
	)
	executeAndReadQuery(acraCon, "select * from customer", nil, &nameQueryResult, &searchQueryResult, &field1QueryResult, &field2QueryResult, &pointQueryResult)
	assert.Equal(nameArg, nameQueryResult)
	assert.Equal(searchArg, searchQueryResult)
	assert.Equal(field1Arg, field1QueryResult)
	assert.Equal(field2Arg, field2QueryResult)
	assert.True(len(pointQueryResult) > 0)

	var (
		nameSearchResult   string
		searchResult       string
		field1SearchResult int
		field2SearchResult int64
		pointSearchResult  []byte
	)
	executeAndReadQuery(acraCon, "select * from customer where searchable = ?", []interface{}{searchArg}, &nameSearchResult, &searchResult, &field1SearchResult, &field2SearchResult, &pointSearchResult)
	assert.Equal(nameArg, nameSearchResult)
	assert.Equal(searchArg, searchResult)
	assert.Equal(field1Arg, field1SearchResult)
	assert.Equal(field2Arg, field2SearchResult)
	assert.True(len(pointSearchResult) > 0)
}

func openConnection(dbConfig tests.DatabaseConfig, port int) *sql.DB {
	connectionString := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", dbConfig.User, dbConfig.Password, dbConfig.DBHost, port, dbConfig.Database)
	dbCon, err := sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	err = dbCon.Ping()
	if err != nil {
		log.Fatal(err)
	}

	return dbCon
}

func executeQuery(con *sql.DB, query string, args ...interface{}) {
	_, err := con.Exec(query, args...)
	if err != nil {
		log.Fatal(err)
	}
}

func executeAndReadQuery(con *sql.DB, query string, args []interface{}, target ...interface{}) {
	rows, err := con.Query(query, args...)
	defer rows.Close()
	if err != nil {
		log.Fatal(err)
	}

	for rows.Next() {
		err := rows.Scan(target...)
		if err != nil {
			panic(err)
		}
	}
}
