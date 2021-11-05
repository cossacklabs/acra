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
}

type columnInfo struct {
	index          int
	alias          string
	binary         bool
	dataBinarySize int
}

// Index return index of column in a row start from 0 and from left
func (info columnInfo) Index() int {
	return info.index
}

// DataBinarySize return size of data
func (info columnInfo) DataBinarySize() int {
	return info.dataBinarySize
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
func NewColumnInfo(index int, alias string, binaryFormat bool, size int) ColumnInfo {
	return columnInfo{index: index, alias: alias, binary: binaryFormat, dataBinarySize: size}
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
	SubscribeOnColumnDecryption(i int, subscriber DecryptionSubscriber)
	SubscribeOnAllColumnsDecryption(subscriber DecryptionSubscriber)
	Unsubscribe(DecryptionSubscriber)
}

// ColumnDecryptionObserver is a simple ColumnDecryptionNotifier implementation.
type ColumnDecryptionObserver struct {
	perColumn  map[int][]DecryptionSubscriber
	allColumns []DecryptionSubscriber
}

// NewColumnDecryptionObserver makes a new observer.
func NewColumnDecryptionObserver() ColumnDecryptionObserver {
	// Reserve some memory for a typical amount of subscribers.
	return ColumnDecryptionObserver{
		perColumn:  make(map[int][]DecryptionSubscriber, 10),
		allColumns: make([]DecryptionSubscriber, 0, 5),
	}
}

// SubscribeOnColumnDecryption subscribes for notifications about the column, indexed from left to right starting with zero.
func (o *ColumnDecryptionObserver) SubscribeOnColumnDecryption(column int, subscriber DecryptionSubscriber) {
	subscribers := o.perColumn[column]
	for _, existing := range subscribers {
		if existing == subscriber {
			return
		}
	}
	o.perColumn[column] = append(subscribers, subscriber)
}

// SubscribeOnAllColumnsDecryption subscribes for notifications on each column.
func (o *ColumnDecryptionObserver) SubscribeOnAllColumnsDecryption(subscriber DecryptionSubscriber) {
	o.allColumns = append(o.allColumns, subscriber)
}

// Unsubscribe a subscriber from all notifications.
func (o *ColumnDecryptionObserver) Unsubscribe(subscriber DecryptionSubscriber) {
	for column, observers := range o.perColumn {
		for i, existing := range observers {
			if existing == subscriber {
				o.perColumn[column] = append(observers[:i], observers[i+1:]...)
				break
			}
		}
	}
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
func (o *ColumnDecryptionObserver) OnColumnDecryption(ctx context.Context, column int, data []byte) ([]byte, error) {
	var err error
	// Avoid creating a map entry if it does not exist.
	subscribers, _ := o.perColumn[column]
	for _, subscriber := range subscribers {
		ctx, data, err = subscriber.OnColumn(ctx, data)
		if err != nil {
			logrus.WithField("subscriber", subscriber.ID()).WithError(err).Errorln("OnColumn error")
			return data, err
		}
	}
	for _, subscriber := range o.allColumns {
		ctx, data, err = subscriber.OnColumn(ctx, data)
		if err != nil {
			logrus.WithField("subscriber", subscriber.ID()).WithError(err).Errorln("OnColumn error")
			return data, err
		}
	}
	return data, nil
}
