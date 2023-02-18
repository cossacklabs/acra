//go:build integration && postgresql
// +build integration,postgresql

package postgresql

import (
	"bytes"
	"context"
	"fmt"
	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/postgresql/testutils"
	encryptorConfig "github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/pseudonymization"
	common2 "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/pseudonymization/storage"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/utils/tests"
	"github.com/cossacklabs/acra/utils/tests/acra-server"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
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

func getFreePortForListener(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	assert.Nil(t, listener.Close())
	return listener.Addr().(*net.TCPAddr).Port
}

func TestSequenceParsePackets(t *testing.T) {
	const timeout = time.Millisecond * 200
	freePort := getFreePortForListener(t)
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
	acraServer := acra_server.NewAcraServer(t, serverConfig, serverProxyFactory, freePort)
	go func() {
		acraServer.Start(ctx)
		t.Log("Finished")
	}()
	defer cancel()
	defer func() {
		acraServer.Close()
		t.Log("Closed")
	}()

	tests.CheckConnection(t, fmt.Sprintf("localhost:%d", freePort))
	frontendConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", freePort))
	assert.Nil(err)
	assert.Nil(frontendConn.SetDeadline(time.Now().Add(timeout)))
	t.Cleanup(func() {
		frontendConn.Close()
		t.Log("Frontend closed")
	})
	frontend := pgproto3.NewFrontend(frontendConn, frontendConn)

	testData1 := []byte("test data 1")
	testData2 := 2
	dbConfig := tests.GetDatabaseConfig(t)
	row1 := testutils.NewCollectDataRowsStep(1)
	row2 := testutils.NewCollectDataRowsStep(1)
	// register two prepared statements and execute them in the opposite order as single group of packets to verify that acra-server
	// applies correct ColumnEncryptionConfig
	steps := []testutils.Step{
		// authenticate
		testutils.NewAuthStep(dbConfig.Database, dbConfig.User, dbConfig.Password),
		// prepare schema
		testutils.SendMessage(&pgproto3.Query{String: "drop table if exists mytable; drop table if exists mytable2; create table if not exists mytable(id serial primary key, data bytea); " +
			"create table if not exists mytable2(id serial primary key, data integer);"}),
		testutils.NewFlushStep(),
		testutils.WaitForStep(&pgproto3.ReadyForQuery{}),

		testutils.SendMessage(&pgproto3.Parse{Name: "p1", Query: "insert into mytable (id, data) values (default, $1) returning data"}),
		testutils.SendMessage(&pgproto3.Parse{Name: "p2", Query: "insert into mytable2 (id, data) values (default, $1) returning data"}),
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
	logging.SetLogLevel(logging.LogDebug)
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

	workingDirectory := tests.GetSourceRootDirectory(t)
	tlsConfig, err := network.NewTLSConfig("localhost",
		filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"),
		filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.key"),
		filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.crt"),
		1, nil)
	assert.Nil(t, err)
	pgConfig, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s",
		dbConfig.DBHost, dbConfig.Port, dbConfig.Database, dbConfig.User, dbConfig.Password))
	assert.Nil(err)
	pgConfig.TLSConfig = tlsConfig
	conn, err := pgx.ConnectConfig(ctx, pgConfig)
	assert.Nil(err)
	assert.Nil(conn.Ping(ctx))
	t.Cleanup(func() {
		conn.Close(ctx)
		t.Log("Closed pg conn")
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

type Frontend interface {
	*pgproto3.Frontend
	Close() error
}

type frontend struct {
	*pgproto3.Frontend
	conn net.Conn
}

func (f *frontend) Close() error {
	return f.conn.Close()
}
