package base

import "context"

// ColumnInfo interface describe available metadata for column
type ColumnInfo interface {
	Index() int
	Alias() string
}

type columnInfo struct {
	index int
	alias string
}

// Index return index of column in a row start from 0 and from left
func (info columnInfo) Index() int {
	return info.index
}
// Alias return column alias from database response if available otherwise should be empty string
func (info columnInfo) Alias() string {
	return info.alias
}
// NewColumnInfo return ColumnInfo implementation for metadata
func NewColumnInfo(index int, alias string) ColumnInfo {
	return columnInfo{index: index, alias: alias}
}

type columnInfoKey struct{}

// NewContextWithColumnInfo return new context with assigned column metadata
func NewContextWithColumnInfo(ctx context.Context, info ColumnInfo) context.Context {
	return context.WithValue(ctx, columnInfoKey{}, info)
}

// ClientZoneInfo store metadata of matched client/zone id and zonemode
type ClientZoneInfo struct {
	ClientID []byte
	ZoneID   []byte
	WithZone bool
}

type clientZoneInfoKey struct{}

// NewContextWithClientZoneInfo return new context with assigned ClientZoneInfo
func NewContextWithClientZoneInfo(ctx context.Context, clientID, zoneID []byte, withZone bool) context.Context {
	return context.WithValue(ctx, clientZoneInfoKey{}, ClientZoneInfo{ClientID: clientID, ZoneID: zoneID, WithZone: withZone})
}
// ClientZoneInfoFromContext return ClientZoneInfo and true if was assigned, otherwise empty ClientZoneInfo and false
func ClientZoneInfoFromContext(ctx context.Context) (ClientZoneInfo, bool) {
	v, ok := ctx.Value(clientZoneInfoKey{}).(ClientZoneInfo)
	return v, ok
}

// ColumnInfoFromContext return ColumnInfo and true if was assigned, otherwise empty ColumnInfo and false
func ColumnInfoFromContext(ctx context.Context) (ColumnInfo, bool) {
	info, ok := ctx.Value(columnInfoKey{}).(ColumnInfo)
	return info, ok
}

// DecryptionSubscriber interface to subscribe on column's data in db responses
type DecryptionSubscriber interface {
	OnColumn(context.Context, []byte) (context.Context, []byte, error)
}

// ColumnDecryptionNotifier interface to subscribe/unsubscribe on OnColumn events
type ColumnDecryptionNotifier interface {
	SubscribeOnColumnDecryption(i int, subscriber DecryptionSubscriber)
	SubscribeOnAllColumnsDecryption(subscriber DecryptionSubscriber)
	Unsubscribe(DecryptionSubscriber)
}
