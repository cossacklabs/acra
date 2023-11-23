/*
Copyright 2019, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package base

import (
	"errors"
	"sync"

	"github.com/sirupsen/logrus"

	decryptor "github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
)

// ErrInconsistentPlaceholder is returned when a placeholder refers to multiple different columns.
var ErrInconsistentPlaceholder = errors.New("inconsistent placeholder usage")

// ErrInvalidPlaceholder is returned when Acra cannot parse SQL placeholder expression.
var ErrInvalidPlaceholder = errors.New("invalid placeholder value")

// ColumnInfo info object that represent column data
type ColumnInfo struct {
	Name  string
	Table string
	Alias string
}

const queryDataItemKey = "query_data_items"

// SaveQueryDataItemsToClientSession save slice of QueryDataItem into ClientSession
func SaveQueryDataItemsToClientSession(session decryptor.ClientSession, items []*QueryDataItem) {
	session.SetData(queryDataItemKey, items)
}

// DeleteQueryDataItemsFromClientSession delete items from ClientSession
func DeleteQueryDataItemsFromClientSession(session decryptor.ClientSession) {
	session.DeleteData(queryDataItemKey)
}

// QueryDataItemsFromClientSession return QueryDataItems from ClientSession if saved otherwise nil
func QueryDataItemsFromClientSession(session decryptor.ClientSession) []*QueryDataItem {
	data, ok := session.GetData(queryDataItemKey)
	if !ok {
		return nil
	}
	items, ok := data.([]*QueryDataItem)
	if ok {
		return items
	}
	return nil
}

var bindPlaceholdersPool = sync.Pool{New: func() interface{} {
	return make(map[int]config.ColumnEncryptionSetting, 32)
}}

const placeholdersSettingKey = "bind_encryption_settings"

// PlaceholderSettingsFromClientSession return stored in client session ColumnEncryptionSettings related to placeholders
// or create new and save in session
func PlaceholderSettingsFromClientSession(session decryptor.ClientSession) map[int]config.ColumnEncryptionSetting {
	data, ok := session.GetData(placeholdersSettingKey)
	if !ok {
		//logger := logging.GetLoggerFromContext(session.Context())
		value := bindPlaceholdersPool.Get().(map[int]config.ColumnEncryptionSetting)
		//logger.WithField("session", session).WithField("value", value).Debugln("Create placeholders")
		session.SetData(placeholdersSettingKey, value)
		return value
	}
	items, ok := data.(map[int]config.ColumnEncryptionSetting)
	if ok {
		return items
	}
	return nil
}

// DeletePlaceholderSettingsFromClientSession delete items from ClientSession
func DeletePlaceholderSettingsFromClientSession(session decryptor.ClientSession) {
	data := PlaceholderSettingsFromClientSession(session)
	if data == nil {
		logrus.Warningln("Invalid type of PlaceholderSettings")
		session.DeleteData(placeholdersSettingKey)
		// do nothing because it's invalid
		return
	}
	for key := range data {
		delete(data, key)
	}
	bindPlaceholdersPool.Put(data)
	session.DeleteData(placeholdersSettingKey)
}
