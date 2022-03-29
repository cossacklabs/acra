package mysql

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	tokens "github.com/cossacklabs/acra/pseudonymization/common"
	"strconv"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
)

// ErrStatementNotFound Err returned by prepared statement registry.
var ErrStatementNotFound = errors.New("no prepared statement with given statement-id")

// PreparedStatementRegistry is a MySQL PreparedStatementRegistry.
type PreparedStatementRegistry struct {
	statements map[string]base.PreparedStatement
}

// NewPreparedStatementRegistry makes a new empty prepared statement registry.
func NewPreparedStatementRegistry() *PreparedStatementRegistry {
	return &PreparedStatementRegistry{
		statements: make(map[string]base.PreparedStatement),
	}
}

// StatementByID returns a prepared statement from the registry by its id, if it exists.
func (r *PreparedStatementRegistry) StatementByID(stmtID string) (base.PreparedStatement, error) {
	if s, ok := r.statements[stmtID]; ok {
		return s, nil
	}
	return nil, ErrStatementNotFound
}

// AddStatement adds a prepared statement to the registry.
// If an existing statement with the same name exists, it is replaced with the new one.
func (r *PreparedStatementRegistry) AddStatement(statement base.PreparedStatement) {
	r.statements[statement.Name()] = statement
}

// PreparedStatement is a MySQL PreparedStatement.
type PreparedStatement struct {
	name         string
	sqlString    string
	paramsNum    int
	sqlStatement sqlparser.Statement
}

// NewPreparedStatement makes a new prepared statement.
func NewPreparedStatement(response *PrepareStatementResponse, sqlString string, sqlStatement sqlparser.Statement) *PreparedStatement {
	return &PreparedStatement{
		name:         strconv.FormatUint(uint64(response.StatementID), 10),
		sqlString:    sqlString,
		sqlStatement: sqlStatement,
		paramsNum:    int(response.ParamsNum),
	}
}

// Name return prepared statement name
func (s *PreparedStatement) Name() string {
	return s.name
}

// ParamsNum return number of prepared statements params
func (s *PreparedStatement) ParamsNum() int {
	return s.paramsNum
}

// Query returns the prepared query, in its parsed form.
func (s *PreparedStatement) Query() sqlparser.Statement {
	return s.sqlStatement
}

// QueryText returns sqlString of the prepared query, as provided by the client.
func (s *PreparedStatement) QueryText() string {
	return s.sqlString
}

type mysqlBoundValue struct {
	paramType Type
	textData  []byte
	format    base.BoundValueFormat
}

// GetType return actual type of base.BoundValue
func (m *mysqlBoundValue) GetType() byte {
	return byte(m.paramType)
}

// NewMysqlCopyTextBoundValue create base.BoundValue with copied input data
func NewMysqlCopyTextBoundValue(data []byte, format base.BoundValueFormat, paramType Type) base.BoundValue {
	var newData []byte
	if data != nil {
		newData = make([]byte, len(data))
		copy(newData, data)
	}

	return &mysqlBoundValue{textData: newData, format: format, paramType: paramType}
}

// NewMysqlBoundValue create base.BoundValue implementation object based on provided textData and paramType
func NewMysqlBoundValue(data []byte, format base.BoundValueFormat, paramType Type) (base.BoundValue, int, error) {
	// if we cant find amount of stored bytes for the paramType assume that it is length encoded string
	storageBytes, ok := NumericTypesStorageBytes[paramType]
	if !ok {
		value, n, err := LengthEncodedString(data)
		if err != nil {
			return nil, 0, err
		}
		textData := make([]byte, len(value))
		copy(textData, value)

		return &mysqlBoundValue{textData: textData, format: format, paramType: paramType}, n, nil
	}

	switch paramType {
	case TypeNull:
		// do nothing
		return &mysqlBoundValue{textData: nil, format: format, paramType: paramType}, int(storageBytes), nil
	case TypeTiny:
		var numericValue int8
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(int64(numericValue), 10))
		return &mysqlBoundValue{textData: value, format: format, paramType: paramType}, int(storageBytes), nil
	case TypeShort, TypeYear:
		var numericValue int16
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(int64(numericValue), 10))
		return &mysqlBoundValue{textData: value, format: format, paramType: paramType}, int(storageBytes), nil
	case TypeInt24, TypeLong:
		var numericValue int32
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(int64(numericValue), 10))
		return &mysqlBoundValue{textData: value, format: format, paramType: paramType}, int(storageBytes), nil
	case TypeLongLong:
		var numericValue int64
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatInt(numericValue, 10))
		return &mysqlBoundValue{textData: value, format: format, paramType: paramType}, int(storageBytes), nil
	case TypeFloat:
		var numericValue float32
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatFloat(float64(numericValue), 'G', -1, 32))
		return &mysqlBoundValue{textData: value, format: format, paramType: paramType}, int(storageBytes), nil
	case TypeDouble:
		var numericValue float64
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &numericValue)
		if err != nil {
			return nil, 0, err
		}
		value := []byte(strconv.FormatFloat(numericValue, 'G', -1, 64))
		return &mysqlBoundValue{textData: value, format: format, paramType: paramType}, int(storageBytes), nil

	default:
		return nil, 0, fmt.Errorf("found unknown Type in MySQL response packet")
	}
}

// Format return BoundValue format
func (m *mysqlBoundValue) Format() base.BoundValueFormat {
	return m.format
}

// Copy create new base.BoundValue with copied textData
func (m *mysqlBoundValue) Copy() base.BoundValue {
	return NewMysqlCopyTextBoundValue(m.textData, m.format, m.paramType)
}

// SetData set new value to BoundValue using ColumnEncryptionSetting if provided
func (m *mysqlBoundValue) SetData(newData []byte, setting config.ColumnEncryptionSetting) error {
	m.textData = newData

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
			m.paramType = TypeLong
		case tokens.TokenType_Int64:
			m.paramType = TypeLongLong
		}
	}
	return nil
}

// GetData return BoundValue using ColumnEncryptionSetting if provided
func (m *mysqlBoundValue) GetData(_ config.ColumnEncryptionSetting) ([]byte, error) {
	return m.textData, nil
}

// Encode format result BoundValue data
func (m *mysqlBoundValue) Encode() (encoded []byte, err error) {
	storageBytes, ok := NumericTypesStorageBytes[m.paramType]
	if !ok {
		return PutLengthEncodedString(m.textData), nil
	}
	// separate error variable for output error from case statements
	// to not overlap with new err variables inside
	// additionally to fix "ineffassign" linter issues
	var outErr error
	encoded = make([]byte, storageBytes)
	switch m.paramType {
	case TypeNull:
		if m.textData != nil {
			outErr = errors.New("NULL not kept NULL")
		}
	case TypeTiny:
		intValue, err := strconv.ParseInt(string(m.textData), 10, 8)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int8(intValue))
	case TypeShort, TypeYear:
		intValue, err := strconv.ParseInt(string(m.textData), 10, 16)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int16(intValue))

	case TypeInt24, TypeLong:
		intValue, err := strconv.ParseInt(string(m.textData), 10, 32)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, int32(intValue))

	case TypeLongLong:
		intValue, err := strconv.ParseInt(string(m.textData), 10, 64)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, intValue)

	case TypeFloat:
		floatValue, err := strconv.ParseFloat(string(m.textData), 32)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, float32(floatValue))

	case TypeDouble:
		floatValue, err := strconv.ParseFloat(string(m.textData), 64)
		if err != nil {
			return nil, err
		}
		outErr = binary.Write(bytes.NewBuffer(encoded[:0]), binary.LittleEndian, floatValue)

	default:
		outErr = fmt.Errorf("found unknown Type in MySQL response packet")
	}

	return encoded, outErr
}
