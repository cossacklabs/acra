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

func TestSequenceParsePackets(t *testing.T) {
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

	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeBlob), &types.BlobDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeString), &types.StringDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeLong), &types.LongDataTypeEncoder{})
	type_awareness.RegisterMySQLDataTypeIDEncoder(uint32(base_mysql.TypeLongLong), &types.LongLongDataTypeEncoder{})

	schemaConfig := `
schemas:
  - table: customer
    columns:
      - name
      - field_int
      - field_int2
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

	assert.Nil(err)
	dbConfig := tests.GetDatabaseConfig(t)

	dbCon := openConnection(dbConfig, dbConfig.Port)
	acraCon := openConnection(dbConfig, freePort)

	var (
		nameArg   = "test_name"
		searchArg = "search_arg"
		field1Arg = 12345
		field2Arg = 12345678901
	)
	executeQuery(dbCon, "CREATE TABLE IF NOT EXISTS customer(name blob, searchable blob, field_int blob, field_int2 blob);")
	executeQuery(dbCon, "TRUNCATE table customer;")
	executeQuery(acraCon, "insert into customer (name, searchable, field_int, field_int2) values (?, ?, ?, ?);", nameArg, searchArg, field1Arg, field2Arg)

	var (
		nameResult   string
		searchResult string
		field1Result int
		field2Result int64
	)
	executeAndReadQuery(acraCon, "select * from customer", &nameResult, &searchResult, &field1Result, &field2Result)
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

func executeAndReadQuery(con *sql.DB, query string, target ...interface{}) {
	rows, err := con.Query(query)
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
