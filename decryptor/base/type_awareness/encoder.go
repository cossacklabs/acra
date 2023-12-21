package type_awareness

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/base/config/common"
)

// DataTypeFormat represent common interface about DB type
type DataTypeFormat interface {
	IsBinaryFormat() bool
	IsBinaryDataOperation() bool
	GetDefaultDataValue() *string
	GetDBDataTypeID() uint32
	GetColumnName() string
	GetResponseOnFail() common.ResponseOnFail
}

// DataTypeEncoder main interface for encoding DB related types
type DataTypeEncoder interface {
	Encode(ctx context.Context, data []byte, format DataTypeFormat) (context.Context, []byte, error)
	EncodeOnFail(ctx context.Context, format DataTypeFormat) (context.Context, []byte, error)
	Decode(ctx context.Context, data []byte, format DataTypeFormat) (context.Context, []byte, error)
	ValidateDefaultValue(value *string) error
}

var (
	lock                    = sync.Mutex{}
	pgSQLDataTypeIDEncoders = map[uint32]DataTypeEncoder{}
	mySQLDataTypeIDEncoders = map[uint32]DataTypeEncoder{}
)

// GetMySQLDataTypeIDEncoders return DataTypeEncoders map for MySQL
func GetMySQLDataTypeIDEncoders() map[uint32]DataTypeEncoder {
	return mySQLDataTypeIDEncoders
}

// GetPostgreSQLDataTypeIDEncoders return DataTypeEncoders map for PostgreSQL
func GetPostgreSQLDataTypeIDEncoders() map[uint32]DataTypeEncoder {
	return pgSQLDataTypeIDEncoders
}

// RegisterPostgreSQLDataTypeIDEncoder register new DataTypeEncoder for PostgreSQL in pgSQLDataTypeIDEncoders map
func RegisterPostgreSQLDataTypeIDEncoder(dataTypeID uint32, encoder DataTypeEncoder) {
	lock.Lock()
	pgSQLDataTypeIDEncoders[dataTypeID] = encoder
	lock.Unlock()
	logrus.WithField("data-type-id", dataTypeID).Debug("Registered config DataTypeEncoder")
}

// RegisterMySQLDataTypeIDEncoder register new DataTypeEncoder for MySQL in mySQLDataTypeIDEncoders map
func RegisterMySQLDataTypeIDEncoder(dataTypeID uint32, encoder DataTypeEncoder) {
	lock.Lock()
	mySQLDataTypeIDEncoders[dataTypeID] = encoder
	lock.Unlock()
	logrus.WithField("data-type-id", dataTypeID).Debug("Registered config DataTypeEncoder")
}
