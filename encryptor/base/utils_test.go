package base

import (
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/cossacklabs/acra/decryptor/base/mocks"
	"github.com/cossacklabs/acra/encryptor/base/config"
)

func TestPlaceholderSettings(t *testing.T) {
	clientSession := &mocks.ClientSession{}
	sessionData := make(map[string]interface{}, 2)
	clientSession.On("GetData", mock.Anything).Return(func(key string) interface{} {
		return sessionData[key]
	}, func(key string) bool {
		_, ok := sessionData[key]
		return ok
	})
	clientSession.On("DeleteData", mock.Anything).Run(func(args mock.Arguments) {
		delete(sessionData, args[0].(string))
	})
	clientSession.On("SetData", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		sessionData[args[0].(string)] = args[1]
	})

	sessionData[placeholdersSettingKey] = "trash"

	data := PlaceholderSettingsFromClientSession(clientSession)
	if data != nil {
		t.Fatal("Expect nil for value with invalid type")
	}
	DeletePlaceholderSettingsFromClientSession(clientSession)

	// get new initialized map
	data = PlaceholderSettingsFromClientSession(clientSession)
	// set some data
	data[0] = &config.BasicColumnEncryptionSetting{}
	data[1] = &config.BasicColumnEncryptionSetting{}

	newData := PlaceholderSettingsFromClientSession(clientSession)
	if len(newData) != len(data) {
		t.Fatal("Unexpected map with different size")
	}
	// clear data, force to return map to the pool cleared from data
	DeletePlaceholderSettingsFromClientSession(clientSession)

	// we expect that will be returned same value from sync.Pool and check that it's cleared
	newData = PlaceholderSettingsFromClientSession(clientSession)
	if len(newData) != 0 {
		t.Fatal("Map's data wasn't cleared")
	}
	if len(newData) != len(data) {
		t.Fatal("Source map's data wasn't cleared")
	}
}
