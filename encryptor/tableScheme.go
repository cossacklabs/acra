/*
Copyright 2018, Cossack Labs Limited

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

package encryptor

import "gopkg.in/yaml.v2"

type TableSchemeStore interface {
	GetTableSchema(tableName string) *TableScheme
}

type storeConfig struct {
	Schemas []*TableScheme
}

type MapTableSchemeStore struct {
	schemas map[string]*TableScheme
}

func MapTableSchemeStoreFromConfig(config []byte) (*MapTableSchemeStore, error) {
	storeConfig := &storeConfig{}
	if err := yaml.Unmarshal(config, &storeConfig); err != nil {
		return nil, err
	}
	mapSchemas := make(map[string]*TableScheme, len(storeConfig.Schemas))
	for _, schema := range storeConfig.Schemas {
		mapSchemas[schema.TableName] = schema
	}
	return &MapTableSchemeStore{mapSchemas}, nil
}

func (store *MapTableSchemeStore) GetTableSchema(tableName string) *TableScheme {
	schema, ok := store.schemas[tableName]
	if ok {
		return schema
	}
	return nil
}

type TableScheme struct {
	TableName           string   `yaml:"table"`
	Columns             []string `yaml:"columns"`
	EncryptedColumns    []string `yaml:"encrypted"`
	mapEncryptedColumns map[string]struct{}
}

func (schema *TableScheme) initMap() {
	mapEncryptedColumns := make(map[string]struct{})
	for _, column := range schema.EncryptedColumns {
		mapEncryptedColumns[column] = struct{}{}
	}
	schema.mapEncryptedColumns = mapEncryptedColumns
}

func (schema *TableScheme) NeedToEncrypt(columnName string) bool {
	if schema.mapEncryptedColumns == nil {
		schema.initMap()
	}
	_, ok := schema.mapEncryptedColumns[columnName]
	return ok
}
