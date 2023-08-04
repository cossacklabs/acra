package mysql

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/sqlparser"
)

type testDecryptor struct{}

func (t testDecryptor) SetClientID([]byte) {
	panic("implement me")
}

func (t testDecryptor) OnNewClientID([]byte) {
	panic("implement me")
}

func (t testDecryptor) SetLogger(*logrus.Entry) {
	panic("implement me")
}

func (t testDecryptor) MatchBeginTag(byte) bool {
	panic("implement me")
}

func (t testDecryptor) IsMatched() bool {
	panic("implement me")
}

func (t testDecryptor) Reset() {
	panic("implement me")
}

func (t testDecryptor) GetMatched() []byte {
	panic("implement me")
}

func (t testDecryptor) ReadSymmetricKey(*keys.PrivateKey, io.Reader) ([]byte, []byte, error) {
	panic("implement me")
}

func (t testDecryptor) ReadSymmetricKeyRotated([]*keys.PrivateKey, io.Reader) ([]byte, []byte, error) {
	panic("implement me")
}

func (t testDecryptor) ReadData([]byte, []byte, io.Reader) ([]byte, error) {
	panic("implement me")
}

func (t testDecryptor) GetTagBeginLength() int {
	panic("implement me")
}

func (t testDecryptor) ID() string {
	panic("implement me")
}

func (t testDecryptor) OnColumn(context.Context, []byte) (context.Context, []byte, error) {
	panic("implement me")
}

func (t testDecryptor) SetKeyStore(keystore.DecryptionKeyStore) {
	panic("implement me")
}

func (t testDecryptor) GetPrivateKey() (*keys.PrivateKey, error) {
	panic("implement me")
}

func (t testDecryptor) GetPrivateKeys() ([]*keys.PrivateKey, error) {
	panic("implement me")
}

func (t testDecryptor) IsWholeMatch() bool {
	panic("implement me")
}

func (t testDecryptor) SetWholeMatch(bool) {
	panic("implement me")
}

func (t testDecryptor) DecryptBlock([]byte) ([]byte, error) {
	panic("implement me")
}

func (t testDecryptor) SkipBeginInBlock(block []byte) ([]byte, error) {
	panic("implement me")
}

func (t testDecryptor) BeginTagIndex([]byte) (int, int) {
	panic("implement me")
}

func (t testDecryptor) SetDataProcessor(processor base.DataProcessor) {
	return
}

type tableSchemaStore struct{ empty bool }

func (*tableSchemaStore) GetDatabaseSettings() config.DatabaseSettings {
	panic("implement me")
}

func (*tableSchemaStore) GetTableSchema(tableName string) config.TableSchema {
	panic("implement me")
}

func (*tableSchemaStore) GetGlobalSettingsMask() config.SettingMask {
	return config.SettingMask(0)
}

type stubSession struct{}

func (s stubSession) GetData(s2 string) (interface{}, bool) {
	panic("implement me")
}

func (s stubSession) SetData(s2 string, i interface{}) {
	panic("implement me")
}

func (s stubSession) DeleteData(s2 string) {
	panic("implement me")
}

func (s stubSession) HasData(s2 string) bool {
	panic("implement me")
}

func (stubSession) Context() context.Context {
	return context.TODO()
}

func (stubSession) ClientConnection() net.Conn {
	return nil
}

func (stubSession) DatabaseConnection() net.Conn {
	return nil
}

func (stubSession) PreparedStatementRegistry() base.PreparedStatementRegistry {
	return nil
}

func (stubSession) SetPreparedStatementRegistry(registry base.PreparedStatementRegistry) {
}

func (stubSession) ProtocolState() interface{} {
	return nil
}

func (stubSession) SetProtocolState(state interface{}) {
}

func TestEncryptorTurnOnOff(t *testing.T) {
	emptyStore := &tableSchemaStore{true}
	nonEmptyStore := &tableSchemaStore{false}
	parser := sqlparser.New(sqlparser.ModeStrict)
	setting := base.NewProxySetting(parser, emptyStore, nil, nil, nil, nil)
	proxyFactory, err := NewProxyFactory(setting, nil, nil)
	if err != nil {
		t.Fatal(setting)
	}
	proxy, err := proxyFactory.New(nil, &stubSession{})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.RegisteredObserversCount() > 2 {
		t.Fatal("Unexpected observers count")
	}

	setting = base.NewProxySetting(parser, nonEmptyStore, nil, nil, nil, nil)
	proxyFactory, err = NewProxyFactory(setting, nil, nil)
	if err != nil {
		t.Fatal(setting)
	}
	proxy, err = proxyFactory.New(nil, &stubSession{})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.RegisteredObserversCount() != 2 {
		t.Fatal("Unexpected observers count")
	}
}
