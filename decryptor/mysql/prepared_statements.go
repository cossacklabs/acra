package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	base_mysql "github.com/cossacklabs/acra/decryptor/mysql/base"
	encryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
	tokens "github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
)

// PreparedStatement is a prepared statement, ready to be executed.
// It can be either a textual SQL statement from "PREPARE", or a database protocol equivalent.
type PreparedStatement interface {
	Name() string
	Query() sqlparser.Statement
	QueryText() string
	ParamsNum() int
}

// ErrStatementNotFound Err returned by prepared statement registry.
var ErrStatementNotFound = errors.New("no prepared statement with given statement-id")

// PreparedStatementItem represent an item to store in PreparedStatementRegistry
type PreparedStatementItem struct {
	stmt                PreparedStatement
	querySelectSettings []*encryptor.QueryDataItem
}

// NewPreparedStatementItem create a new PreparedStatementItem
func NewPreparedStatementItem(stmt PreparedStatement, querySelectSettings []*encryptor.QueryDataItem) PreparedStatementItem {
	return PreparedStatementItem{
		stmt:                stmt,
		querySelectSettings: querySelectSettings,
	}
}

// Name return PreparedStatementItem name
func (r *PreparedStatementItem) Name() string {
	return r.stmt.Name()
}

// Statement return PreparedStatementItem statememt
func (r *PreparedStatementItem) Statement() PreparedStatement {
	return r.stmt
}

// QuerySettings return PreparedStatementItem querySettings
func (r *PreparedStatementItem) QuerySettings() []*encryptor.QueryDataItem {
	return r.querySelectSettings
}

// PreparedStatementRegistry is a MySQL PreparedStatementRegistry.
type PreparedStatementRegistry struct {
	statements map[string]PreparedStatementItem
}

// NewPreparedStatementRegistry makes a new empty prepared statement registry.
func NewPreparedStatementRegistry() *PreparedStatementRegistry {
	return &PreparedStatementRegistry{
		statements: make(map[string]PreparedStatementItem),
	}
}

// StatementByID returns a prepared statement from the registry by its id, if it exists.
func (r *PreparedStatementRegistry) StatementByID(stmtID string) (PreparedStatementItem, error) {
	if s, ok := r.statements[stmtID]; ok {
		return s, nil
	}
	return PreparedStatementItem{}, ErrStatementNotFound
}

// DeleteStatementByID returns a prepared statement from the registry by its id, if it exists.
func (r *PreparedStatementRegistry) DeleteStatementByID(stmtID string) bool {
	if _, ok := r.statements[stmtID]; ok {
		delete(r.statements, stmtID)
		return ok
	}
	return false
}

// AddStatement adds a prepared statement to the registry.
// If an existing statement with the same name exists, it is replaced with the new one.
func (r *PreparedStatementRegistry) AddStatement(statement PreparedStatementItem) {
	r.statements[statement.Name()] = statement
}

// MySQLPreparedStatement is a MySQL PreparedStatement.
type MySQLPreparedStatement struct {
	name         string
	sqlString    string
	paramsNum    int
	sqlStatement sqlparser.Statement
}

// NewPreparedStatement makes a new prepared statement.
func NewPreparedStatement(statementID uint32, paramsNum uint16, sqlString string, sqlStatement sqlparser.Statement) *MySQLPreparedStatement {
	return &MySQLPreparedStatement{
		name:         strconv.FormatUint(uint64(statementID), 10),
		sqlString:    sqlString,
		sqlStatement: sqlStatement,
		paramsNum:    int(paramsNum),
	}
}

// NewPreparedStatementWithName makes a new prepared statement with name and zero paramsNum
func NewPreparedStatementWithName(name string, sqlString string, sqlStatement sqlparser.Statement) *MySQLPreparedStatement {
	return &MySQLPreparedStatement{
		name:         name,
		sqlString:    sqlString,
		sqlStatement: sqlStatement,
	}
}

// Name return prepared statement name
func (s *MySQLPreparedStatement) Name() string {
	return s.name
}

// ParamsNum return number of prepared statements params
func (s *MySQLPreparedStatement) ParamsNum() int {
	return s.paramsNum
}

// Query returns the prepared query, in its parsed form.
func (s *MySQLPreparedStatement) Query() sqlparser.Statement {
	return s.sqlStatement
}

// QueryText returns sqlString of the prepared query, as provided by the client.
func (s *MySQLPreparedStatement) QueryText() string {
	return s.sqlString
}

type mysqlBoundValue struct {
	paramType base_mysql.Type
	data      []byte
	format    base.BoundValueFormat
}

// GetType return actual type of base.BoundValue
func (m *mysqlBoundValue) GetType() byte {
	return byte(m.paramType)
}

// NewMysqlCopyTextBoundValue create base.BoundValue with copied input data
func NewMysqlCopyTextBoundValue(data []byte, format base.BoundValueFormat, paramType base_mysql.Type) base.BoundValue {
	var newData []byte
	if data != nil {
		newData = make([]byte, len(data))
		copy(newData, data)
	}

	return &mysqlBoundValue{data: newData, format: format, paramType: paramType}
}

// NewMysqlBoundValue create base.BoundValue implementation object based on provided data and paramType
func NewMysqlBoundValue(data []byte, format base.BoundValueFormat, paramType base_mysql.Type) (base.BoundValue, int, error) {
	// if we cant find amount of stored bytes for the paramType assume that it is length encoded string
	storageBytes, ok := base_mysql.NumericTypesStorageBytes[paramType]
	if !ok {
		value, n, err := base_mysql.LengthEncodedString(data)
		if err != nil {
			return nil, 0, err
		}
		textData := make([]byte, len(value))
		copy(textData, value)

		return &mysqlBoundValue{data: textData, format: format, paramType: paramType}, n, nil
	}

	switch paramType {
	case base_mysql.TypeNull:
		// do nothing
		return &mysqlBoundValue{data: nil, format: format, paramType: paramType}, int(storageBytes), nil
	case base_mysql.TypeTiny:
		var numericValue int8
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(int64(numericValue), 10))
		return &mysqlBoundValue{data: value, format: format, paramType: paramType}, int(storageBytes), nil
	case base_mysql.TypeShort, base_mysql.TypeYear:
		var numericValue int16
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(int64(numericValue), 10))
		return &mysqlBoundValue{data: value, format: format, paramType: paramType}, int(storageBytes), nil
	case base_mysql.TypeInt24, base_mysql.TypeLong:
		var numericValue int32
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(int64(numericValue), 10))
		return &mysqlBoundValue{data: value, format: format, paramType: paramType}, int(storageBytes), nil
	case base_mysql.TypeLongLong:
		var numericValue int64
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(numericValue, 10))
		return &mysqlBoundValue{data: value, format: format, paramType: paramType}, int(storageBytes), nil
	case base_mysql.TypeFloat:
		var numericValue float32
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatFloat(float64(numericValue), 'G', -1, 32))
		return &mysqlBoundValue{data: value, format: format, paramType: paramType}, int(storageBytes), nil
	case base_mysql.TypeDouble:
		var numericValue float64
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatFloat(numericValue, 'G', -1, 64))
		return &mysqlBoundValue{data: value, format: format, paramType: paramType}, int(storageBytes), nil

	default:
		return nil, 0, fmt.Errorf("found unknown Type in MySQL response packet")
	}
}

// Format return BoundValue format
func (m *mysqlBoundValue) Format() base.BoundValueFormat {
	return m.format
}

// Copy create new base.BoundValue with copied data
func (m *mysqlBoundValue) Copy() base.BoundValue {
	return NewMysqlCopyTextBoundValue(m.data, m.format, m.paramType)
}

// SetData set new value to BoundValue using ColumnEncryptionSetting if provided
func (m *mysqlBoundValue) SetData(newData []byte, setting config.ColumnEncryptionSetting) error {
	// means that we set encrypted data
	if !bytes.Equal(m.data, newData) {
		m.paramType = base_mysql.TypeBlob
		m.data = newData
	}

	if setting == nil {
		return nil
	}

	// In case of tokenization happened, even if the driver sent value as Tiny
	// we need to update mysql types in the result packet to Long/LongLong as Acra supports only int32/int64 tokenization
	// also mysql cast less sized type to higher one automatically.
	switch m.format {
	case base.BinaryFormat:
		switch setting.GetTokenType() {
		case tokens.TokenType_Int32:
			m.paramType = base_mysql.TypeLong
		case tokens.TokenType_Int64:
			m.paramType = base_mysql.TypeLongLong
		}
	}
	return nil
}

// GetData return BoundValue using ColumnEncryptionSetting if provided
func (m *mysqlBoundValue) GetData(_ config.ColumnEncryptionSetting) ([]byte, error) {
	return m.data, nil
}

// Encode format result BoundValue data
func (m *mysqlBoundValue) Encode() (encoded []byte, err error) {
	storageBytes, ok := base_mysql.NumericTypesStorageBytes[m.paramType]
	if !ok {
		return base_mysql.PutLengthEncodedString(m.data), nil
	}
	// separate error variable for output error from case statements
	// to not overlap with new err variables inside
	// additionally to fix "ineffassign" linter issues
	var outErr error
	encoded = make([]byte, storageBytes)
	switch m.paramType {
	case base_mysql.TypeNull:
		if m.data != nil {
			outErr = errors.New("NULL not kept NULL")
		}
	case base_mysql.TypeTiny:
		intValue, err := strconv.ParseInt(utils.BytesToString(m.data), 10, 8)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int8(intValue))
	case base_mysql.TypeShort, base_mysql.TypeYear:
		intValue, err := strconv.ParseInt(utils.BytesToString(m.data), 10, 16)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int16(intValue))

	case base_mysql.TypeInt24, base_mysql.TypeLong:
		intValue, err := strconv.ParseInt(utils.BytesToString(m.data), 10, 32)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int32(intValue))

	case base_mysql.TypeLongLong:
		intValue, err := strconv.ParseInt(utils.BytesToString(m.data), 10, 64)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, intValue)

	case base_mysql.TypeFloat:
		floatValue, err := strconv.ParseFloat(utils.BytesToString(m.data), 32)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, float32(floatValue))

	case base_mysql.TypeDouble:
		floatValue, err := strconv.ParseFloat(utils.BytesToString(m.data), 64)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, floatValue)

	default:
		outErr = fmt.Errorf("found unknown Type in base_mysql.response packet")
	}

	return encoded, outErr
}

// PreparedStatementFieldTracker track and replace DataType for column and param ColumnDefinition
type PreparedStatementFieldTracker struct {
	proxyHandler *Handler
	// shared value that indicates number of param packet
	paramsCounter int
	columnsNum    uint16
}

// NewPreparedStatementFieldTracker create new PreparedStatementFieldTracker
func NewPreparedStatementFieldTracker(handler *Handler, columnNum uint16) PreparedStatementFieldTracker {
	return PreparedStatementFieldTracker{
		proxyHandler: handler,
		columnsNum:   columnNum,
	}
}

// ParamsTrackHandler implements ResponseHandler to track prepare statement params
func (p *PreparedStatementFieldTracker) ParamsTrackHandler(ctx context.Context, packet *Packet, _, clientConnection net.Conn) error {
	clientSession := base.ClientSessionFromContext(ctx)
	if clientSession == nil {
		p.proxyHandler.logger.Warningln("Packet without ClientSession in context")
	}

	items := encryptor.PlaceholderSettingsFromClientSession(clientSession)
	if items == nil {
		p.proxyHandler.logger.Debugln("Packet with registered recognized encryption settings")
	}

	if packet.IsEOF() {
		p.proxyHandler.logger.Debugln("ParamsTrackHandler EOF", "column_num", p.columnsNum, "stmt_id", p.proxyHandler.protocolState.GetStmtID())

		// if columns_num > 0 column definition block will follow
		// https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
		if p.columnsNum > 0 {
			p.proxyHandler.setQueryHandler(p.ColumnsTrackHandler)
		} else {
			p.proxyHandler.setQueryHandler(p.proxyHandler.QueryResponseHandler)
		}

		if _, err := clientConnection.Write(packet.Dump()); err != nil {
			p.proxyHandler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
				Debugln("Can't proxy output")
		}
		return nil
	}

	field, err := ParseResultField(packet, p.proxyHandler.Capabilities.IsSetMariaDBClientExtendedTypeInfo())
	if err != nil {
		p.proxyHandler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Errorln("Can't parse result field")
		return err
	}

	setting, ok := items[p.paramsCounter]
	if ok {
		newFieldType, ok := mapEncryptedTypeToField(setting.GetDBDataTypeID())
		if ok {
			field.originType = field.Type
			field.Type = base_mysql.Type(newFieldType)
			field.changed = true
		}
	}

	if _, err := clientConnection.Write(field.Dump()); err != nil {
		p.proxyHandler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
			Debugln("Can't proxy output")
		return err
	}

	p.paramsCounter++
	return nil
}

// ColumnsTrackHandler implements ResponseHandler to track prepared statement columns
func (p *PreparedStatementFieldTracker) ColumnsTrackHandler(ctx context.Context, packet *Packet, _, clientConnection net.Conn) error {
	p.proxyHandler.logger.Debugln("Parse column ColumnDefinition")
	if packet.IsEOF() {
		// There are different behaviour for prepared statements processing for MariaDB and MySQL
		// For MySQL, we should process PreparedStatements response and then
		// switch QueryHandler to QueryResponseHandler on receiving Execute packet from client.
		// For MariaDB we can receive Execute packet without finishing the Prepare packet response processing.
		// (https://mariadb.com/kb/en/com_stmt_execute/#specific-1-statement-id-value)
		// So we switch QueryHandler to QueryResponseHandler as data should be followed next
		// It`s safe to switch QueryHandler to QueryResponseHandler here as in case of any new packet type received from client
		// QueryHandler will be switched to the appropriate one from ProxyClient goroutine.
		p.proxyHandler.setQueryHandler(p.proxyHandler.QueryResponseHandler)

		if _, err := clientConnection.Write(packet.Dump()); err != nil {
			p.proxyHandler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
				Debugln("Can't proxy output")
		}
		return nil
	}

	field, err := ParseResultField(packet, p.proxyHandler.Capabilities.IsSetMariaDBClientExtendedTypeInfo())
	if err != nil {
		p.proxyHandler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorProtocolProcessing).WithError(err).Errorln("Can't parse result field")
		return err
	}

	// updating field type according to DataType provided in schemaStore
	updateFieldEncodedType(field, p.proxyHandler.setting.TableSchemaStore())

	p.proxyHandler.protocolState.AddColumnDescription(field)

	if _, err := clientConnection.Write(field.Dump()); err != nil {
		p.proxyHandler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorNetworkWrite).
			Debugln("Can't proxy output")
		return err
	}

	return nil
}
