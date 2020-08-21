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

package config

import (
	"gopkg.in/yaml.v2"
)

// TableSchemaStore fetches schema for encryptable tables in the database.
type TableSchemaStore interface {
	// GetTableSchema returns schema for given table if configured, or nil otherwise.
	GetTableSchema(tableName string) TableSchema
	// IsEmpty returns true if the store does not have any schemas.
	IsEmpty() bool
}

// TableSchema describes a table and its encryption settings per column.
type TableSchema interface {
	Name() string
	Columns() []string
	NeedToEncrypt(columnName string) bool
	// GetColumnEncryptionSettings fetches encryption settings for given column,
	// or returns nil if the column should not be encrypted.
	GetColumnEncryptionSettings(columnName string) ColumnEncryptionSetting
}

type storeConfig struct {
	Schemas []*tableSchema
}

// MapTableSchemaStore store schemas per table name
type MapTableSchemaStore struct {
	schemas map[string]*tableSchema
}

// NewMapTableSchemaStore return new MapTableSchemaStore
func NewMapTableSchemaStore() (*MapTableSchemaStore, error) {
	return &MapTableSchemaStore{make(map[string]*tableSchema)}, nil
}

// MapTableSchemaStoreFromConfig parse config and return MapTableSchemaStore with data from config
func MapTableSchemaStoreFromConfig(config []byte) (*MapTableSchemaStore, error) {
	storeConfig := &storeConfig{}
	if err := yaml.Unmarshal(config, &storeConfig); err != nil {
		return nil, err
	}
	mapSchemas := make(map[string]*tableSchema, len(storeConfig.Schemas))
	for _, schema := range storeConfig.Schemas {
		mapSchemas[schema.TableName] = schema
	}
	return &MapTableSchemaStore{mapSchemas}, nil
}

// GetTableSchema return table schema if exists otherwise nil
func (store *MapTableSchemaStore) GetTableSchema(tableName string) TableSchema {
	// Explicitly check for presence and return explicit "nil" value
	// so that returned interface is "== nil".
	schema, ok := store.schemas[tableName]
	if ok {
		return schema
	}
	return nil
}

// IsEmpty return true if hasn't any schemas
func (store *MapTableSchemaStore) IsEmpty() bool {
	if store.schemas == nil || len(store.schemas) == 0 {
		return true
	}
	return false
}

// ColumnEncryptionSetting describes how to encrypt a table column.
type ColumnEncryptionSetting interface {
	ColumnName() string
	ClientID() []byte
	ZoneID() []byte
}

// BasicColumnEncryptionSetting is a basic set of column encryption settings.
type BasicColumnEncryptionSetting struct {
	Name         string `yaml:"column"`
	UsedClientID string `yaml:"client_id"`
	UsedZoneID   string `yaml:"zone_id"`
}

// ColumnName returns name of the column for which these settings are for.
func (s *BasicColumnEncryptionSetting) ColumnName() string {
	return s.Name
}

// ClientID returns client ID to use when encrypting this column.
func (s *BasicColumnEncryptionSetting) ClientID() []byte {
	return []byte(s.UsedClientID)
}

// ZoneID returns zone ID to use when encrypting this column.
func (s *BasicColumnEncryptionSetting) ZoneID() []byte {
	return []byte(s.UsedZoneID)
}

type tableSchema struct {
	TableName                string                          `yaml:"table"`
	TableColumns             []string                        `yaml:"columns"`
	EncryptionColumnSettings []*BasicColumnEncryptionSetting `yaml:"encrypted"`
	mapEncryptedColumns      map[string]*BasicColumnEncryptionSetting
}

// Name returns the name of the table.
func (schema *tableSchema) Name() string {
	return schema.TableName
}

// Columns returns a list of column names in this table.
func (schema *tableSchema) Columns() []string {
	return schema.TableColumns
}

// initMap create map of columns to encrypt from array
func (schema *tableSchema) initMap() {
	mapEncryptedColumns := make(map[string]*BasicColumnEncryptionSetting)
	for _, column := range schema.EncryptionColumnSettings {
		mapEncryptedColumns[column.Name] = column
	}
	schema.mapEncryptedColumns = mapEncryptedColumns
}

// NeedToEncrypt return true if columnName should be encrypted by config
func (schema *tableSchema) NeedToEncrypt(columnName string) bool {
	if schema.mapEncryptedColumns == nil {
		schema.initMap()
	}
	_, ok := schema.mapEncryptedColumns[columnName]
	return ok
}

// GetColumnEncryptionSettings return setting or nil
func (schema *tableSchema) GetColumnEncryptionSettings(columnName string) ColumnEncryptionSetting {
	if schema.mapEncryptedColumns == nil {
		schema.initMap()
	}
	// Explicitly check for presence and return explicit "nil" value
	// so that returned interface is "== nil".
	setting, ok := schema.mapEncryptedColumns[columnName]
	if ok {
		return setting
	}
	return nil
}
