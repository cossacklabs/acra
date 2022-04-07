package base

import (
	"context"

	"github.com/sirupsen/logrus"
)

// ColumnInfo interface describe available metadata for column
type ColumnInfo interface {
	Index() int
	Alias() string
	IsBinaryFormat() bool
	DataBinarySize() int
	DataBinaryType() byte
	OriginBinaryType() byte
}

type columnInfo struct {
	index            int
	alias            string
	binary           bool
	dataBinarySize   int
	dataBinaryType   byte
	originBinaryType byte
}

// Index return index of column in a row start from 0 and from left
func (info columnInfo) Index() int {
	return info.index
}

// DataBinarySize return size of data
func (info columnInfo) DataBinarySize() int {
	return info.dataBinarySize
}

// DataBinaryType return type of data
func (info columnInfo) DataBinaryType() byte {
	return info.dataBinaryType
}

// OriginBinaryType return type of data
func (info columnInfo) OriginBinaryType() byte {
	return info.originBinaryType
}

// IsBinaryFormat return true if column data in binary DB specific format
func (info columnInfo) IsBinaryFormat() bool {
	return info.binary
}

// Alias return column alias from database response if available otherwise should be empty string
func (info columnInfo) Alias() string {
	return info.alias
}

// NewColumnInfo return ColumnInfo implementation for metadata
func NewColumnInfo(index int, alias string, binaryFormat bool, size int, dataType, originType byte) ColumnInfo {
	return columnInfo{
		index:            index,
		alias:            alias,
		binary:           binaryFormat,
		dataBinarySize:   size,
		dataBinaryType:   dataType,
		originBinaryType: originType,
	}
}

// ColumnInfoFromContext return ColumnInfo and true if was assigned, otherwise empty ColumnInfo and false
func ColumnInfoFromContext(ctx context.Context) (ColumnInfo, bool) {
	accessContext := AccessContextFromContext(ctx)
	info := accessContext.GetColumnInfo()
	return info, info != nil
}

// DecryptionSubscriber interface to subscribe on column's data in db responses
type DecryptionSubscriber interface {
	OnColumn(context.Context, []byte) (context.Context, []byte, error)
	ID() string
}

// ColumnDecryptionNotifier interface to subscribe/unsubscribe on OnColumn events
type ColumnDecryptionNotifier interface {
	SubscribeOnAllColumnsDecryption(subscriber DecryptionSubscriber)
	Unsubscribe(DecryptionSubscriber)
}

// ColumnDecryptionObserver is a simple ColumnDecryptionNotifier implementation.
type ColumnDecryptionObserver struct {
	allColumns []DecryptionSubscriber
}

// NewColumnDecryptionObserver makes a new observer.
func NewColumnDecryptionObserver() ColumnDecryptionObserver {
	// Reserve some memory for a typical amount of subscribers.
	return ColumnDecryptionObserver{
		allColumns: make([]DecryptionSubscriber, 0, 5),
	}
}

// SubscribeOnAllColumnsDecryption subscribes for notifications on each column.
func (o *ColumnDecryptionObserver) SubscribeOnAllColumnsDecryption(subscriber DecryptionSubscriber) {
	o.allColumns = append(o.allColumns, subscriber)
}

// Unsubscribe a subscriber from all notifications.
func (o *ColumnDecryptionObserver) Unsubscribe(subscriber DecryptionSubscriber) {
	for i, existing := range o.allColumns {
		if existing == subscriber {
			o.allColumns = append(o.allColumns[:i], o.allColumns[i+1:]...)
			break
		}
	}
}

// OnColumnDecryption notifies all subscribers about a change in given column, passing the context and data to them.
// Returns the data and error returned by subscribers.
// If a subscriber returns an error, it is immediately returned and other subscribers are not notified.
func (o *ColumnDecryptionObserver) OnColumnDecryption(ctx context.Context, column int, data []byte) (context.Context, []byte, error) {
	var err error
	// Avoid creating a map entry if it does not exist.
	for _, subscriber := range o.allColumns {
		ctx, data, err = subscriber.OnColumn(ctx, data)
		if err != nil {
			logrus.WithField("subscriber", subscriber.ID()).WithError(err).Errorln("OnColumn error")
			return ctx, data, err
		}
	}
	return ctx, data, nil
}

type decryptedCtxKey struct{}

// MarkDecryptedContext save flag in context that data was decrypted
func MarkDecryptedContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, decryptedCtxKey{}, true)
}

// IsDecryptedFromContext return true if data was decrypted related to context
func IsDecryptedFromContext(ctx context.Context) bool {
	return ctx.Value(decryptedCtxKey{}) != nil
}

type errorConvertedDataTypeCtxKey struct{}

// MarkErrorConvertedDataTypeContext save flag in context that was error during data type conversion
func MarkErrorConvertedDataTypeContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, errorConvertedDataTypeCtxKey{}, true)
}

// IsErrorConvertedDataTypeFromContext return true if data was decrypted related to context
func IsErrorConvertedDataTypeFromContext(ctx context.Context) bool {
	return ctx.Value(errorConvertedDataTypeCtxKey{}) != nil
}
