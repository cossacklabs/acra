package postgresql

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	pg_query "github.com/cossacklabs/pg_query_go/v5"
	"github.com/sirupsen/logrus"

	acracensor "github.com/cossacklabs/acra/acra-censor"
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	"github.com/cossacklabs/acra/sqlparser"
)

func TestDataRowLastEmptyColumn(t *testing.T) {
	// data row packet hex dump with 5 columns and last column has length 0
	// check correct processing when last column has length 0 and packetHandler doesn't try to read from connection
	// and doesn't take io.EOF after this
	data, err := hex.DecodeString("44000001f50005000000013100000006686f746a61720000000131000001d33c212d2d20486f746a617220547261636b696e6720436f646520666f7220636f737361636b6c6162732e636f6d202d2d3e0d0a3c7363726970743e0d0a202020202866756e6374696f6e28682c6f2c742c6a2c612c72297b0d0a2020202020202020682e686a3d682e686a7c7c66756e6374696f6e28297b28682e686a2e713d682e686a2e717c7c5b5d292e7075736828617267756d656e7473297d3b0d0a2020202020202020682e5f686a53657474696e67733d7b686a69643a313137373730362c686a73763a367d3b0d0a2020202020202020613d6f2e676574456c656d656e747342795461674e616d6528276865616427295b305d3b0d0a2020202020202020723d6f2e637265617465456c656d656e74282773637269707427293b722e6173796e633d313b0d0a2020202020202020722e7372633d742b682e5f686a53657474696e67732e686a69642b6a2b682e5f686a53657474696e67732e686a73763b0d0a2020202020202020612e617070656e644368696c642872293b0d0a202020207d292877696e646f772c646f63756d656e742c2768747470733a2f2f7374617469632e686f746a61722e636f6d2f632f686f746a61722d272c272e6a733f73763d27293b0d0a3c2f7363726970743e00000000")
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(data)
	writerBuf := bytes.NewBuffer(make([]byte, len(data)))
	writer := bufio.NewWriter(writerBuf)
	packetHandler, err := NewDbSidePacketHandler(reader, writer, logrus.NewEntry(logrus.New()))
	if err != nil {
		t.Fatal(err)
	}
	if err := packetHandler.ReadPacket(); err != nil {
		t.Fatal(err)
	}

	if !packetHandler.IsDataRow() {
		t.Fatal("Must be data row")
	}

	if err := packetHandler.parseColumns(nil); err != nil {
		t.Fatal(err)
	}
}

type testConnection struct {
	buf io.Reader
}

func newTestConn(buf []byte) *testConnection {
	return &testConnection{bytes.NewReader(buf)}
}

func (t *testConnection) Read(b []byte) (n int, err error) {
	return t.buf.Read(b)
}

func (t *testConnection) Write(b []byte) (n int, err error) {
	panic("implement me")
}

func (t *testConnection) Close() error {
	panic("implement me")
}

func (t *testConnection) LocalAddr() net.Addr {
	panic("implement me")
}

func (t *testConnection) RemoteAddr() net.Addr {
	panic("implement me")
}

func (t *testConnection) SetDeadline(time.Time) error {
	panic("implement me")
}

func (t *testConnection) SetReadDeadline(time.Time) error {
	panic("implement me")
}

func (t *testConnection) SetWriteDeadline(time.Time) error {
	panic("implement me")
}

type testOnBindHandler struct {
	query string
	bind  string
}

func (t *testOnBindHandler) ID() string {
	panic("implement me")
}

func (t *testOnBindHandler) OnQuery(ctx context.Context, data postgresql.OnQueryObject) (postgresql.OnQueryObject, bool, error) {
	var err error
	t.query, err = data.Query()
	return data, false, err
}

func (t *testOnBindHandler) OnBind(ctx context.Context, statement *pg_query.ParseResult, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	var err error
	t.bind, err = pg_query.Deparse(statement)
	return values, false, err
}

func TestPreparedStatementRegistering(t *testing.T) {
	parser := sqlparser.New(sqlparser.ModeDefault)
	ctx := context.Background()
	// this query encoded in parsePacket below
	parseQuery := "SELECT t.*, CTID\nFROM public.bla t\nLIMIT 501"
	parseQueryStatement, err := pg_query.Parse(parseQuery)
	if err != nil {
		t.Fatal(err)
	}
	parsePacketHex := `50000000340053454c45435420742e2a2c20435449440a46524f4d207075626c69632e626c6120740a4c494d495420353031000000`
	bindPacketHex := `420000000c0000000000000000`
	testPackets, err := hex.DecodeString(parsePacketHex + bindPacketHex)
	if err != nil {
		t.Fatal(err)
	}
	buffer := bytes.NewBuffer(testPackets)
	connectionSession, err := common.NewClientSession(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxySetting := base.NewProxySetting(parser, nil, nil, nil, acracensor.NewAcraCensor(), nil)
	proxy, err := NewPgProxy(connectionSession, parser, proxySetting)
	if err != nil {
		t.Fatal(err)
	}
	queryObserver := &testOnBindHandler{}
	proxy.AddQueryObserver(queryObserver)
	if len(proxy.registry.statements) != 0 {
		t.Fatal("Invalid length of registered statements")
	}
	logger := logrus.NewEntry(logrus.New())
	packet, err := NewClientSidePacketHandler(buffer, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	// Test as if one of the startup messages is received
	packet.started = true
	if err = packet.ReadClientPacket(); err != nil {
		t.Fatal(err)
	}
	_, err = proxy.handleClientPacket(ctx, packet, logger)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := proxy.registry.StatementByName("")
	if err != nil {
		t.Fatal(err)
	}
	if parseQuery != statement.QueryText() {
		t.Fatalf("'%s' != '%s'\n", parseQuery, statement.QueryText())
	}
	if queryObserver.query != parseQuery {
		t.Fatalf("'%s' != '%s'\n", parseQuery, statement.QueryText())
	}
	// check that after ParsePacket without ParseComplete query already registered
	if len(proxy.registry.statements) != 1 {
		t.Fatal("Invalid length of registered statements")
	}

	if err = packet.ReadClientPacket(); err != nil {
		t.Fatal(err)
	}
	_, err = proxy.handleClientPacket(ctx, packet, logger)
	if err != nil {
		t.Fatal(err)
	}
	// check that same statement was passed as onbind query

	resultQuery, err := pg_query.Deparse(parseQueryStatement)
	if err != nil {
		t.Fatal(err)
	}

	if queryObserver.bind != resultQuery {
		t.Fatalf("'%s' != '%s'\n", parseQuery, statement.QueryText())
	}
}

func TestCorrectColumnToSettingMapping(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	parser := sqlparser.New(sqlparser.ModeDefault)
	ctx := context.Background()

	// two responses one by one
	dbBuffer := bytes.NewBuffer([]byte{})
	dbPacketHandler, err := NewDbSidePacketHandler(dbBuffer, nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	// expected more columns than encryptorQuerySettings
	dbPacketHandler.descriptionBuf = bytes.NewBuffer(
		// some packet dump with columns
		[]byte{0, 14, 0, 0, 0, 3, 114, 97, 119, 0, 0, 0, 10, 105, 110, 99, 108, 117, 100, 101, 65, 108, 108, 0, 0, 0,
			43, 108, 105, 113, 117, 105, 98, 97, 115, 101, 47, 46, 47, 118, 95, 49, 95, 48, 95, 48, 47, 112, 111, 115,
			116, 103, 114, 101, 115, 47, 115, 113, 108, 47, 116, 97, 98, 108, 101, 115, 46, 115, 113, 108, 0, 0, 0, 26,
			50, 48, 50, 51, 45, 49, 48, 45, 48, 51, 32, 49, 52, 58, 49, 56, 58, 50, 56, 46, 53, 56, 52, 55, 57, 50, 0,
			0, 0, 1, 49, 0, 0, 0, 8, 69, 88, 69, 67, 85, 84, 69, 68, 0, 0, 0, 34, 56, 58, 55, 56, 49, 51, 98, 100, 48,
			57, 57, 50, 53, 101, 56, 48, 50, 99, 52, 51, 49, 48, 54, 101, 101, 100, 54, 57, 53, 53, 54, 97, 98, 100, 0,
			0, 0, 3, 115, 113, 108, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 5, 52, 46, 51, 46, 53, 255, 255, 255, 255,
			255, 255, 255, 255, 0, 0, 0, 10, 54, 51, 51, 53, 53, 48, 56, 52, 55, 56},
	)
	dbPacketHandler.descriptionLengthBuf = []byte{0, 0, 0, 110}

	connectionSession, err := common.NewClientSession(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx = base.SetClientSessionToContext(ctx, connectionSession)

	proxySetting := base.NewProxySetting(parser, nil, nil, nil, acracensor.NewAcraCensor(), nil)
	proxy, err := NewPgProxy(connectionSession, parser, proxySetting)
	if err != nil {
		t.Fatal(err)
	}

	settingExtractor, err := NewEncryptionSettingExtractor(ctx, &config.MapTableSchemaStore{})
	if err != nil {
		t.Fatal(err)
	}

	proxy.settingExtractor = settingExtractor
	proxy.protocolState.pendingQueryPackets.Add(queryPacket{
		preparedStatement: &PgPreparedStatement{
			text: "SELECT * FROM public.databasechangelog ORDER BY DATEEXECUTED ASC, ORDEREXECUTED ASC",
		},
		executePacket: &ExecutePacket{},
		bindPacket:    &BindPacket{},
	})

	err = proxy.handleQueryDataPacket(ctx, dbPacketHandler, logger)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMultiplePrepareAtOnce(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	parser := sqlparser.New(sqlparser.ModeDefault)
	ctx := context.Background()

	beginSQL := "BEGIN"
	beginName := "__cossack_begin__"

	selectSQL := "SELECT 1"
	selectName := "__cossack_select__"

	// Build two "parse" packets to simulate delivery of them at once
	clientBuffer := bytes.NewBuffer([]byte{})
	clientWriter := bufio.NewWriter(clientBuffer)
	if err := writePrepare(clientWriter, beginName, beginSQL); err != nil {
		t.Fatal(err)
	}
	if err := writePrepare(clientWriter, selectName, selectSQL); err != nil {
		t.Fatal(err)
	}
	if err := clientWriter.Flush(); err != nil {
		t.Fatal(err)
	}
	clientPacketHandler, err := NewClientSidePacketHandler(clientBuffer, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	clientPacketHandler.started = true

	// two responses one by one
	dbBuffer := bytes.NewBuffer([]byte{})
	dbWriter := bufio.NewWriter(dbBuffer)
	if err := writeZeroPrepareResponse(dbWriter); err != nil {
		t.Fatal(err)
	}
	if err := writeZeroPrepareResponse(dbWriter); err != nil {
		t.Fatal(err)
	}
	if err := dbWriter.Flush(); err != nil {
		t.Fatal(err)
	}
	dbPacketHandler, err := NewDbSidePacketHandler(dbBuffer, nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	connectionSession, err := common.NewClientSession(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxySetting := base.NewProxySetting(parser, nil, nil, nil, acracensor.NewAcraCensor(), nil)
	proxy, err := NewPgProxy(connectionSession, parser, proxySetting)
	if err != nil {
		t.Fatal(err)
	}
	// Client packets are handled first, before responses arrive
	for {
		err := clientPacketHandler.ReadClientPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		_, err = proxy.handleClientPacket(ctx, clientPacketHandler, logger)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Then we handle responses
	for {
		err := dbPacketHandler.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		err = proxy.handleDatabasePacket(ctx, dbPacketHandler, logger)
		if err != nil {
			t.Fatal(err)
		}
	}
	beginStmt, err := proxy.registry.StatementByName(beginName)
	if err != nil {
		t.Fatal(err)
	}

	selectStmt, err := proxy.registry.StatementByName(selectName)
	if err != nil {
		t.Fatal(err)
	}

	if beginSQL != beginStmt.QueryText() {
		t.Fatalf("%q != %q\n", beginSQL, beginStmt.QueryText())
	}

	if selectSQL != selectStmt.QueryText() {
		t.Fatalf("%q != %q\n", selectSQL, selectStmt.QueryText())
	}
}

func TestMultiplePrepareAtOnceWithError(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	parser := sqlparser.New(sqlparser.ModeDefault)
	ctx := context.Background()

	beginSQL := "BEGIN"
	beginName := "__cossack_begin__"

	failSQL := "PLEASE FAIL"
	failName := "__cossack_fail__"

	selectSQL := "SELECT 1"
	selectName := "__cossack_select__"

	// Build three "parse" packets to simulate delivery of them at once
	clientBuffer := bytes.NewBuffer([]byte{})
	clientWriter := bufio.NewWriter(clientBuffer)
	if err := writePrepare(clientWriter, beginName, beginSQL); err != nil {
		t.Fatal(err)
	}
	if err := writePrepare(clientWriter, failName, failSQL); err != nil {
		t.Fatal(err)
	}
	if err := writePrepare(clientWriter, selectName, selectSQL); err != nil {
		t.Fatal(err)
	}
	if err := clientWriter.Flush(); err != nil {
		t.Fatal(err)
	}
	clientPacketHandler, err := NewClientSidePacketHandler(clientBuffer, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	clientPacketHandler.started = true

	// thre responses one by one: success, error, success
	dbBuffer := bytes.NewBuffer([]byte{})
	dbWriter := bufio.NewWriter(dbBuffer)
	if err := writeZeroPrepareResponse(dbWriter); err != nil {
		t.Fatal(err)
	}
	if err := writeErrorResponse(dbWriter); err != nil {
		t.Fatal(err)
	}
	if err := writeZeroPrepareResponse(dbWriter); err != nil {
		t.Fatal(err)
	}
	if err := dbWriter.Flush(); err != nil {
		t.Fatal(err)
	}
	dbPacketHandler, err := NewDbSidePacketHandler(dbBuffer, nil, logger)
	if err != nil {
		t.Fatal(err)
	}

	connectionSession, err := common.NewClientSession(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxySetting := base.NewProxySetting(parser, nil, nil, nil, acracensor.NewAcraCensor(), nil)
	proxy, err := NewPgProxy(connectionSession, parser, proxySetting)
	if err != nil {
		t.Fatal(err)
	}
	// Client packets are handled first, before responses arrive
	for {
		err := clientPacketHandler.ReadClientPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		_, err = proxy.handleClientPacket(ctx, clientPacketHandler, logger)
		if err != nil {
			pendingParse, err := clientPacketHandler.GetParseData()
			if err != nil {
				t.Fatal(err)
			}
			if pendingParse.Name() != failName {
				t.Fatal(err)
			}
		}
	}

	// Then we handle responses
	for {
		err := dbPacketHandler.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		err = proxy.handleDatabasePacket(ctx, dbPacketHandler, logger)
		if err != nil {
			t.Fatal(err)
		}
	}

	beginStmt, err := proxy.registry.StatementByName(beginName)
	if err != nil {
		t.Fatal(err)
	}

	selectStmt, err := proxy.registry.StatementByName(selectName)
	if err != nil {
		t.Fatal(err)
	}

	_, err = proxy.registry.StatementByName(failName)
	if err == nil {
		t.Fatalf("%q exists but shouldn't", failName)
	}

	if beginSQL != beginStmt.QueryText() {
		t.Fatalf("%q != %q\n", beginSQL, beginStmt.QueryText())
	}

	if selectSQL != selectStmt.QueryText() {
		t.Fatalf("%q != %q\n", selectSQL, selectStmt.QueryText())
	}
}

//
// Utils for crafting the packets
//

func writeUint32(w io.Writer, val uint32) error {
	int32Buff := [4]byte{}
	binary.BigEndian.PutUint32(int32Buff[:], val)
	_, err := w.Write(int32Buff[:])
	return err
}

func writeNullString(w io.Writer, str string) error {
	if _, err := w.Write([]byte(str)); err != nil {
		return err
	}

	_, err := w.Write([]byte{0x00})
	return err
}

const sizeLen = 4
const nullLen = 1

func writeParsePacket(w io.Writer, name string, stmt string) error {
	packet := ParsePacket{
		name:      append([]byte(name), 0x00),
		query:     append([]byte(stmt), 0x00),
		paramsNum: []byte{0x00, 0x00},
		params:    []objectID{},
	}
	serialized := packet.Marshal()
	length := len(serialized) + 4
	if _, err := w.Write([]byte{'P'}); err != nil {
		return err
	}
	if err := writeUint32(w, uint32(length)); err != nil {
		return err
	}
	_, err := w.Write(serialized)
	return err
}

func writeDescribePacket(w io.Writer, name string) error {
	describeType := []byte{'S'}

	_, err := w.Write([]byte{'D'})
	if err != nil {
		return err
	}
	size := sizeLen + len(describeType) + len(name) + nullLen
	err = writeUint32(w, uint32(size))
	if err != nil {
		return err
	}
	_, err = w.Write(describeType)
	if err != nil {
		return err
	}
	return writeNullString(w, name)
}

func writeSyncPacket(w io.Writer) error {
	_, err := w.Write([]byte{
		'S',                    // tag
		0x00, 0x00, 0x00, 0x04, // length
	})
	return err
}

// writePrepare writes sequence of Prepare packets into w:
// - Parse
// - Describe
// - Sync
func writePrepare(w io.Writer, name string, stmt string) error {
	if err := writeParsePacket(w, name, stmt); err != nil {
		return err
	}
	if err := writeDescribePacket(w, name); err != nil {
		return err
	}
	return writeSyncPacket(w)
}

func writeParseComplete(w io.Writer) error {
	_, err := w.Write([]byte{
		'1',                    // tag
		0x00, 0x00, 0x00, 0x04, // length
	})
	return err
}

func writeZeroParamDescription(w io.Writer) error {
	_, err := w.Write([]byte{
		't',                    // tag
		0x00, 0x00, 0x00, 0x06, // length
		0x00, 0x00, // number of params
	})
	return err
}

func writeZeroRowDescription(w io.Writer) error {
	_, err := w.Write([]byte{
		'n',                    // tag
		0x00, 0x00, 0x00, 0x04, // length
	})
	return err
}

// writeZeroPrepareResponse writes response for parse-sequence:
// Parse complete
// Parameter description (with 0 params)
// Row description (with 0 params)
func writeZeroPrepareResponse(w io.Writer) error {
	if err := writeParseComplete(w); err != nil {
		return err
	}
	if err := writeZeroParamDescription(w); err != nil {
		return err
	}
	return writeZeroRowDescription(w)
}

func writeErrorResponse(w io.Writer) error {
	packet, err := NewPgError("something really bad happened")
	if err != nil {
		return err
	}
	_, err = w.Write(packet)
	return err
}
