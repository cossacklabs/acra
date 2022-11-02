package type_awerness

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
)

type DataTypeFormat interface {
	IsBinaryFormat() bool
	IsBinaryDataOperation() bool
}

type DataTypeEncoder interface {
	Encode(ctx context.Context, data []byte, format DataTypeFormat) (context.Context, []byte, error)
	EncodeDefault(ctx context.Context, data []byte, format DataTypeFormat) (context.Context, []byte, error)
	Decode(ctx context.Context, data []byte, format DataTypeFormat) (context.Context, []byte, error)
}

var (
	lock                    = sync.Mutex{}
	pgSQLDataTypeIDEncoders = map[uint32]DataTypeEncoder{}
	mySQLDataTypeIDEncoders = map[uint32]DataTypeEncoder{}
)

func GetMySQLDataTypeIDEncoders() map[uint32]DataTypeEncoder {
	return mySQLDataTypeIDEncoders
}

func GetPostgreSQLDataTypeIDEncoders() map[uint32]DataTypeEncoder {
	return pgSQLDataTypeIDEncoders
}

func RegisterPostgreSQLDataTypeIDEncoder(dataTypeID uint32, encoder DataTypeEncoder) {
	lock.Lock()
	pgSQLDataTypeIDEncoders[dataTypeID] = encoder
	lock.Unlock()
	logrus.WithField("data-type-id", dataTypeID).Debug("Registered config DataTypeEncoder")
}
