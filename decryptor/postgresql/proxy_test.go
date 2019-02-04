package postgresql

import (
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/config"
	"testing"
)

type decryptorFactory struct{}

func (*decryptorFactory) New(clientID []byte) (base.Decryptor, error) {
	return nil, nil
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
	proxy, err := proxyFactory.New(nil, nil, nil, nil)
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
	proxy, err = proxyFactory.New(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.RegisteredObserversCount() != 1 {
		t.Fatal("Unexpected observers count")
	}
}
