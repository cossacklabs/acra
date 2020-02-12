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

// clientZoneInfo store metadata of matched client/zone id and zonemode
type clientZoneInfo struct {
	clientID []byte
	zoneID   []byte
	withZone bool
}

// ClientID return client id
func (info clientZoneInfo) ClientID() []byte {
	return info.clientID
}

// ZoneID return zone id
func (info clientZoneInfo) ZoneID() []byte {
	return info.zoneID
}

// WithZone return true if used zone mode
func (info clientZoneInfo) WithZone() bool {
	return info.withZone
}

// ClientZoneInfo provide access method for data related to decryption metadata
type ClientZoneInfo interface {
	ClientID() []byte
	ZoneID() []byte
	WithZone() bool
}

// NewClientZoneInfo return new ClientZoneInfo implementation with passed data
func NewClientZoneInfo(clientID, zoneID []byte, withZone bool) ClientZoneInfo {
	return clientZoneInfo{
		clientID: clientID,
		zoneID:   zoneID,
		withZone: withZone,
	}
}

type clientZoneInfoKey struct{}

// NewContextWithClientZoneInfo return new context with assigned clientZoneInfo
func NewContextWithClientZoneInfo(ctx context.Context, clientID, zoneID []byte, withZone bool) context.Context {
	return context.WithValue(ctx, clientZoneInfoKey{}, NewClientZoneInfo(clientID, zoneID, withZone))
}

// ClientZoneInfoFromContext return clientZoneInfo and true if was assigned, otherwise empty clientZoneInfo and false
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
