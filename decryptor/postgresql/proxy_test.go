package postgresql

import (
	"context"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"github.com/sirupsen/logrus"
	"io"
	"testing"
)

type testDecryptor struct{}

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

func (t testDecryptor) SetKeyStore(keystore.KeyStore) {
	panic("implement me")
}

func (t testDecryptor) GetPrivateKey() (*keys.PrivateKey, error) {
	panic("implement me")
}

func (t testDecryptor) TurnOnPoisonRecordCheck(bool) {
	panic("implement me")
}

func (t testDecryptor) IsPoisonRecordCheckOn() bool {
	panic("implement me")
}

func (t testDecryptor) SetPoisonCallbackStorage(*base.PoisonCallbackStorage) {
	panic("implement me")
}

func (t testDecryptor) GetPoisonCallbackStorage() *base.PoisonCallbackStorage {
	panic("implement me")
}

func (t testDecryptor) SetZoneMatcher(*zone.Matcher) {
	panic("implement me")
}

func (t testDecryptor) GetZoneMatcher() *zone.Matcher {
	panic("implement me")
}

func (t testDecryptor) GetMatchedZoneID() []byte {
	panic("implement me")
}

func (t testDecryptor) MatchZone(byte) bool {
	panic("implement me")
}

func (t testDecryptor) IsWithZone() bool {
	panic("implement me")
}

func (t testDecryptor) SetWithZone(bool) {
	panic("implement me")
}

func (t testDecryptor) IsMatchedZone() bool {
	panic("implement me")
}

func (t testDecryptor) ResetZoneMatch() {
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

func (t testDecryptor) MatchZoneBlock([]byte) {
	panic("implement me")
}

func (t testDecryptor) CheckPoisonRecord(reader io.Reader) (bool, error) {
	panic("implement me")
}

func (t testDecryptor) BeginTagIndex([]byte) (int, int) {
	panic("implement me")
}

func (t testDecryptor) MatchZoneInBlock([]byte) {
	panic("implement me")
}

func (t testDecryptor) SetDataProcessor(processor base.DataProcessor) {
	return
}

type decryptorFactory struct{}

func (*decryptorFactory) New(clientID []byte) (base.Decryptor, error) {
	return &testDecryptor{}, nil
}

type tableSchemaStore struct{ empty bool }

func (*tableSchemaStore) GetTableSchema(tableName string) *config.TableSchema {
	panic("implement me")
}

func (store *tableSchemaStore) IsEmpty() bool {
	return store.empty
}

func TestEncryptorTurnOnOff(t *testing.T) {
	emptyStore := &tableSchemaStore{true}
	nonEmptyStore := &tableSchemaStore{false}
	setting := base.NewProxySetting(&decryptorFactory{}, emptyStore, nil, nil, nil)
	proxyFactory, err := NewProxyFactory(setting)
	if err != nil {
		t.Fatal(setting)
	}
	proxy, err := proxyFactory.New(context.TODO(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.RegisteredObserversCount() > 0 {
		t.Fatal("Unexpected observers count")
	}

	setting = base.NewProxySetting(&decryptorFactory{}, nonEmptyStore, nil, nil, nil)
	proxyFactory, err = NewProxyFactory(setting)
	if err != nil {
		t.Fatal(setting)
	}
	proxy, err = proxyFactory.New(context.TODO(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.RegisteredObserversCount() != 1 {
		t.Fatal("Unexpected observers count")
	}
}
