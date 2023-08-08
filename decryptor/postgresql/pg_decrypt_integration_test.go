//go:build integration && postgresql
// +build integration,postgresql

package postgresql

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/postgresql/testutils"
	encryptorConfig "github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/pseudonymization"
	common2 "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/utils/tests"
	"github.com/cossacklabs/acra/utils/tests/acra-server"
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
	serverConfig.SetUseClientIDFromCertificate(false)
	assert := assert.New(t)
	assert.Nil(serverConfig.SetStaticClientID(clientID))
	serverKeystore := serverConfig.GetKeyStore()
	assert.Nil(serverKeystore.GenerateClientIDSymmetricKey(clientID))
	// different tables with same columns but different security controls
	schemaConfig := `schemas:
  - table: mytable
    columns:
      - id
      - data
    encrypted:
      - column: data
  - table: mytable2
    columns:
      - id
      - data
    encrypted:
      - column: data
        token_type: int32
`
	schemaStore, err := encryptorConfig.MapTableSchemaStoreFromConfig([]byte(schemaConfig), false)
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

	workingDirectory := tests.GetSourceRootDirectory(t)
	tlsConfig, err := network.NewTLSConfig("localhost",
		filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"),
		filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.key"),
		filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.crt"),
		1, nil)
	assert.Nil(err)
	dbConfig := tests.GetDatabaseConfig(t)
	pgConfig, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s",
		dbConfig.DBHost, dbConfig.Port, dbConfig.Database, dbConfig.User, dbConfig.Password))
	assert.Nil(err)
	pgConfig.TLSConfig = tlsConfig

	tests.CheckConnection(t, fmt.Sprintf("localhost:%d", freePort))
	t.Run("use named portals/cursors", func(t *testing.T) {
		conn, err := pgx.ConnectConfig(ctx, pgConfig)
		assert.Nil(err)
		assert.Nil(conn.Ping(ctx))
		t.Cleanup(func() {
			conn.Close(ctx)
		})
		frontendConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", freePort))
		assert.Nil(err)
		assert.Nil(frontendConn.SetDeadline(time.Now().Add(timeout)))
		t.Cleanup(func() {
			frontendConn.Close()
		})
		frontend := testutils.NewFrontend(frontendConn, frontendConn)
		t.Cleanup(func() {
			frontend.Close()
		})

		testData1 := []byte("test data 1")
		testData2 := 2
		row1 := testutils.NewCollectDataRowsStep(1)
		row2 := testutils.NewCollectDataRowsStep(1)
		// register two prepared statements and execute them in the opposite order as single group of packets to verify that acra-server
		// applies correct ColumnEncryptionConfig
		steps := []testutils.Step{
			// authenticate
			testutils.NewAuthStep(ctx, tlsConfig, dbConfig.Database, dbConfig.User, dbConfig.Password),
			// prepare schema
			testutils.SendMessage(&pgproto3.Query{String: "drop table if exists mytable; drop table if exists mytable2; create table if not exists mytable(id serial primary key, data bytea); " +
				"create table if not exists mytable2(id serial primary key, data integer);"}),
			testutils.NewFlushStep(),
			testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

			testutils.SendMessage(&pgproto3.Parse{Name: "p1", Query: "insert into mytable (id, data) values (default, $1) returning data"}),
			testutils.SendMessage(&pgproto3.Parse{Name: "p2", Query: "insert into mytable2 (id, data) values (default, $1) returning data"}),

			// test with named portals/cursors
			testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "p2", PreparedStatement: "p2",
				// integer in the text format
				Parameters: [][]byte{[]byte(strconv.Itoa(testData2))}, ParameterFormatCodes: []int16{0}}),
			// valid utf8 string can be passed as is for bytea type
			testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "p1", Parameters: [][]byte{testData1}}),
			testutils.SendMessage(&pgproto3.Execute{Portal: "p2"}),
			testutils.SendMessage(&pgproto3.Execute{Portal: "p1"}),
			testutils.SendMessage(&pgproto3.Sync{}),
			testutils.NewFlushStep(),

			testutils.WaitForStep(&pgproto3.BindComplete{}),
			testutils.WaitForStep(&pgproto3.BindComplete{}),
			row2,
			testutils.WaitForStep(&pgproto3.CommandComplete{}),
			row1,
			testutils.WaitForStep(&pgproto3.CommandComplete{}),
			testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

			testutils.SendMessage(&pgproto3.Terminate{}),
			testutils.NewFlushStep(),
		}
		script := testutils.Script{steps}
		err = script.Run(frontend)
		assert.Nil(err)
		// check that we took decrypted data as is
		assert.Equal(len(row1.GetRows()), 1)
		assert.Equal(len(row2.GetRows()), 1)
		value, err := utils.DecodeEscaped(row1.GetRows()[0][0])
		assert.Nil(err)
		assert.True(bytes.Equal(value, testData1))
		value, err = utils.DecodeEscaped(row2.GetRows()[0][0])
		assert.Nil(err)
		intValue, err := strconv.Atoi(string(value))
		assert.Nil(err)
		assert.Equal(intValue, testData2)

		var byteaResult []byte
		err = conn.QueryRow(ctx, `select data from mytable`).Scan(&byteaResult)
		assert.Nil(err)
		assert.NotEqual(byteaResult, testData1)
		// validate that received AcraBlock instead of source data
		matcher := crypto.NewEnvelopeMatcher()
		assert.True(matcher.Match(byteaResult))
		assert.Nil(err)

		// validate that data from the database received in encrypted form
		var integerResult int
		err = conn.QueryRow(ctx, `select data from mytable2`).Scan(&integerResult)
		assert.Nil(err)
		assert.NotEqual(integerResult, testData2)
	})

	t.Run("use unnamed portals/cursors", func(t *testing.T) {
		conn, err := pgx.ConnectConfig(ctx, pgConfig)
		assert.Nil(err)
		assert.Nil(conn.Ping(ctx))
		t.Cleanup(func() {
			conn.Close(ctx)
		})
		frontendConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", freePort))
		assert.Nil(err)
		assert.Nil(frontendConn.SetDeadline(time.Now().Add(timeout)))
		t.Cleanup(func() {
			frontendConn.Close()
		})
		frontend := testutils.NewFrontend(frontendConn, frontendConn)
		t.Cleanup(func() {
			frontend.Close()
		})

		testData1 := []byte("test data 1")
		testData2 := 2
		row1 := testutils.NewCollectDataRowsStep(1)
		row2 := testutils.NewCollectDataRowsStep(1)
		// register two prepared statements and execute them in the opposite order as single group of packets to verify that acra-server
		// applies correct ColumnEncryptionConfig
		steps := []testutils.Step{
			// authenticate
			testutils.NewAuthStep(ctx, tlsConfig, dbConfig.Database, dbConfig.User, dbConfig.Password),
			// prepare schema
			testutils.SendMessage(&pgproto3.Query{String: "drop table if exists mytable; drop table if exists mytable2; create table if not exists mytable(id serial primary key, data bytea); " +
				"create table if not exists mytable2(id serial primary key, data integer);"}),
			testutils.NewFlushStep(),
			testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

			testutils.SendMessage(&pgproto3.Parse{Name: "p1", Query: "insert into mytable (id, data) values (default, $1) returning data"}),
			testutils.SendMessage(&pgproto3.Parse{Name: "p2", Query: "insert into mytable2 (id, data) values (default, $1) returning data"}),

			// test with named portals/cursors
			testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "p2",
				// integer in the text format
				Parameters: [][]byte{[]byte(strconv.Itoa(testData2))}, ParameterFormatCodes: []int16{0}}),
			testutils.SendMessage(&pgproto3.Execute{Portal: ""}),
			// valid utf8 string can be passed as is for bytea type
			testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "p1", Parameters: [][]byte{testData1}}),
			testutils.SendMessage(&pgproto3.Execute{Portal: ""}),
			testutils.SendMessage(&pgproto3.Sync{}),
			testutils.NewFlushStep(),

			testutils.WaitForStep(&pgproto3.BindComplete{}),
			row2,
			testutils.WaitForStep(&pgproto3.CommandComplete{}),
			testutils.WaitForStep(&pgproto3.BindComplete{}),
			row1,
			testutils.WaitForStep(&pgproto3.CommandComplete{}),
			testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

			testutils.SendMessage(&pgproto3.Terminate{}),
			testutils.NewFlushStep(),
		}
		script := testutils.Script{steps}
		err = script.Run(frontend)
		assert.Nil(err)
		// check that we took decrypted data as is
		assert.Equal(len(row1.GetRows()), 1)
		assert.Equal(len(row2.GetRows()), 1)
		value, err := utils.DecodeEscaped(row1.GetRows()[0][0])
		assert.Nil(err)
		assert.True(bytes.Equal(value, testData1))
		value, err = utils.DecodeEscaped(row2.GetRows()[0][0])
		assert.Nil(err)
		intValue, err := strconv.Atoi(string(value))
		assert.Nil(err)
		assert.Equal(intValue, testData2)

		var byteaResult []byte
		err = conn.QueryRow(ctx, `select data from mytable`).Scan(&byteaResult)
		assert.Nil(err)
		assert.NotEqual(byteaResult, testData1)
		// validate that received AcraBlock instead of source data
		matcher := crypto.NewEnvelopeMatcher()
		assert.True(matcher.Match(byteaResult))
		assert.Nil(err)

		// validate that data from the database received in encrypted form
		var integerResult int
		err = conn.QueryRow(ctx, `select data from mytable2`).Scan(&integerResult)
		assert.Nil(err)
		assert.NotEqual(integerResult, testData2)
	})

	t.Run("handle error response", func(t *testing.T) {
		conn, err := pgx.ConnectConfig(ctx, pgConfig)
		assert.Nil(err)
		assert.Nil(conn.Ping(ctx))
		t.Cleanup(func() {
			conn.Close(ctx)
		})
		frontendConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", freePort))
		assert.Nil(err)
		assert.Nil(frontendConn.SetDeadline(time.Now().Add(timeout)))
		t.Cleanup(func() {
			frontendConn.Close()
		})
		frontend := testutils.NewFrontend(frontendConn, frontendConn)
		t.Cleanup(func() {
			frontend.Close()
		})
		testData := 2
		row := testutils.NewCollectDataRowsStep(1)

		steps := []testutils.Step{
			// authenticate
			testutils.NewAuthStep(ctx, tlsConfig, dbConfig.Database, dbConfig.User, dbConfig.Password),
			// prepare schema
			testutils.SendMessage(&pgproto3.Query{String: "drop table if exists mytable2; create table if not exists mytable2(id serial primary key, data integer);"}),
			testutils.NewFlushStep(),
			testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

			testutils.SendMessage(&pgproto3.Parse{Name: "p1", Query: "insert into mytable2 (id, data) values (default, $1) returning data"}),
			testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "p1",
				// integer in the text format
				Parameters: [][]byte{[]byte(strconv.Itoa(testData))}, ParameterFormatCodes: []int16{0}}),

			// drop table and try to fetch data from it
			testutils.SendMessage(&pgproto3.Query{String: "drop table if exists mytable2; "}),
			testutils.SendMessage(&pgproto3.Execute{Portal: ""}),
			testutils.SendMessage(&pgproto3.Sync{}),
			testutils.NewFlushStep(),

			testutils.WaitForStep(&pgproto3.ParseComplete{}),
			testutils.WaitForStep(&pgproto3.BindComplete{}),
			// result of SimpleQuery with drop table
			testutils.WaitForStep(&pgproto3.ReadyForQuery{'I'}),
			testutils.ExpectAnyMessage(&pgproto3.ErrorResponse{}),
			testutils.ExpectMessage(&pgproto3.ReadyForQuery{'I'}),

			// verify that previously parsed statement continue to work
			testutils.SendMessage(&pgproto3.Query{String: "create table if not exists mytable2(id serial primary key, data integer);"}),
			testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "p1",
				// integer in the text format
				Parameters: [][]byte{[]byte(strconv.Itoa(testData))}, ParameterFormatCodes: []int16{0}}),
			testutils.SendMessage(&pgproto3.Execute{Portal: ""}),
			testutils.SendMessage(&pgproto3.Sync{}),
			testutils.NewFlushStep(),

			// create table
			testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

			testutils.WaitForStep(&pgproto3.BindComplete{}),
			row,
			testutils.WaitForStep(&pgproto3.CommandComplete{}),
			testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

			testutils.SendMessage(&pgproto3.Terminate{}),
			testutils.NewFlushStep(),
		}
		script := testutils.Script{steps}
		err = script.Run(frontend)
		assert.Nil(err)

		// check that we took decrypted data as is
		assert.Equal(len(row.GetRows()), 1)
		value, err := utils.DecodeEscaped(row.GetRows()[0][0])
		assert.Nil(err)
		intValue, err := strconv.Atoi(string(value))
		assert.Nil(err)
		assert.Equal(intValue, testData)

		// validate that data from the database received in encrypted form
		var integerResult int
		err = conn.QueryRow(ctx, `select data from mytable2`).Scan(&integerResult)
		assert.Nil(err)
		assert.NotEqual(integerResult, testData)
	})
}

func TestSequenceParsePacketsWithUnnamedPortals(t *testing.T) {
	const timeout = time.Hour * 200
	freePort := tests.GetFreePortForListener(t)
	serverConfig := acra_server.NewDefaultAcraServerConfig(t)
	clientID := []byte("clientID")
	serverConfig.SetUseClientIDFromCertificate(false)
	assert := assert.New(t)
	assert.Nil(serverConfig.SetStaticClientID(clientID))
	serverKeystore := serverConfig.GetKeyStore()
	assert.Nil(serverKeystore.GenerateClientIDSymmetricKey(clientID))
	// different tables with same columns but different security controls
	schemaConfig := `schemas:
  - table: mytable
    columns:
      - id
      - data
    encrypted:
      - column: data
  - table: mytable2
    columns:
      - id
      - data
    encrypted:
      - column: data
        token_type: int32
`
	schemaStore, err := encryptorConfig.MapTableSchemaStoreFromConfig([]byte(schemaConfig), false)
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

	tests.CheckConnection(t, fmt.Sprintf("localhost:%d", freePort))
	frontendConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", freePort))
	assert.Nil(err)
	assert.Nil(frontendConn.SetDeadline(time.Now().Add(timeout)))
	t.Cleanup(func() {
		frontendConn.Close()
	})
	frontend := testutils.NewFrontend(frontendConn, frontendConn)

	testData1 := []byte("test data 1")
	testData2 := 2
	dbConfig := tests.GetDatabaseConfig(t)
	row1 := testutils.NewCollectDataRowsStep(1)
	row2 := testutils.NewCollectDataRowsStep(1)
	workingDirectory := tests.GetSourceRootDirectory(t)
	tlsConfig, err := network.NewTLSConfig("localhost",
		filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"),
		filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.key"),
		filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.crt"),
		1, nil)
	assert.Nil(err)
	// register two prepared statements and execute them in the opposite order as single group of packets to verify that acra-server
	// applies correct ColumnEncryptionConfig
	steps := []testutils.Step{
		// authenticate
		testutils.NewAuthStep(ctx, tlsConfig, dbConfig.Database, dbConfig.User, dbConfig.Password),
		// prepare schema
		testutils.SendMessage(&pgproto3.Query{String: "drop table if exists mytable; drop table if exists mytable2; create table if not exists mytable(id serial primary key, data bytea); " +
			"create table if not exists mytable2(id serial primary key, data integer);"}),
		testutils.NewFlushStep(),
		testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

		testutils.SendMessage(&pgproto3.Parse{Name: "p1", Query: "insert into mytable (id, data) values (default, $1) returning data"}),
		testutils.SendMessage(&pgproto3.Parse{Name: "p2", Query: "insert into mytable2 (id, data) values (default, $1) returning data"}),

		testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "p2",
			// integer in the text format
			Parameters: [][]byte{[]byte(strconv.Itoa(testData2))}, ParameterFormatCodes: []int16{0}}),
		testutils.SendMessage(&pgproto3.Execute{Portal: ""}),
		// valid utf8 string can be passed as is for bytea type
		testutils.SendMessage(&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "p1", Parameters: [][]byte{testData1}}),
		testutils.SendMessage(&pgproto3.Execute{Portal: ""}),
		testutils.SendMessage(&pgproto3.Sync{}),
		testutils.NewFlushStep(),

		testutils.ExpectMessage(&pgproto3.ParseComplete{}),
		testutils.ExpectMessage(&pgproto3.ParseComplete{}),

		testutils.WaitForStep(&pgproto3.BindComplete{}),
		row2,
		testutils.WaitForStep(&pgproto3.CommandComplete{}),
		testutils.WaitForStep(&pgproto3.BindComplete{}),
		row1,
		testutils.WaitForStep(&pgproto3.CommandComplete{}),
		testutils.WaitForStep(&pgproto3.ReadyForQuery{}),
		testutils.SendMessage(&pgproto3.Terminate{}),
		testutils.NewFlushStep(),
	}
	script := testutils.Script{steps}
	err = script.Run(frontend)
	assert.Nil(err)
	// check that we took decrypted data as is
	assert.Equal(len(row1.GetRows()), 1)
	assert.Equal(len(row2.GetRows()), 1)
	value, err := utils.DecodeEscaped(row1.GetRows()[0][0])
	assert.Nil(err)
	assert.True(bytes.Equal(value, testData1))
	value, err = utils.DecodeEscaped(row2.GetRows()[0][0])
	assert.Nil(err)
	intValue, err := strconv.Atoi(string(value))
	assert.Nil(err)
	assert.Equal(intValue, testData2)

	pgConfig, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s",
		dbConfig.DBHost, dbConfig.Port, dbConfig.Database, dbConfig.User, dbConfig.Password))
	assert.Nil(err)
	pgConfig.TLSConfig = tlsConfig
	conn, err := pgx.ConnectConfig(ctx, pgConfig)
	assert.Nil(err)
	assert.Nil(conn.Ping(ctx))
	t.Cleanup(func() {
		conn.Close(ctx)
	})

	var byteaResult []byte
	err = conn.QueryRow(ctx, `select data from mytable`).Scan(&byteaResult)
	assert.Nil(err)
	assert.NotEqual(byteaResult, testData1)
	// validate that received AcraBlock instead of source data
	matcher := crypto.NewEnvelopeMatcher()
	assert.True(matcher.Match(byteaResult))
	assert.Nil(err)

	// validate that data from the database received in encrypted form
	var integerResult int
	err = conn.QueryRow(ctx, `select data from mytable2`).Scan(&integerResult)
	assert.Nil(err)
	assert.NotEqual(integerResult, testData2)
}
