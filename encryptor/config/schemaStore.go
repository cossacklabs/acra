/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"gopkg.in/yaml.v2"
)

// TableSchemaStore fetches schema for encryptable tables in the database.
type TableSchemaStore interface {
	GetDatabaseSettings() DatabaseSettings
	// GetTableSchema returns schema for given table if configured, or nil otherwise.
	GetTableSchema(tableName string) TableSchema
	GetGlobalSettingsMask() SettingMask
}

// defaultValues store default values for config
type defaultValues struct {
	CryptoEnvelope       *CryptoEnvelopeType `yaml:"crypto_envelope"`
	ReEncryptToAcraBlock *bool               `yaml:"reencrypting_to_acrablocks"`
}

// GetCryptoEnvelope returns type of crypto envelope
func (d defaultValues) GetCryptoEnvelope() CryptoEnvelopeType {
	if d.CryptoEnvelope == nil {
		return CryptoEnvelopeTypeAcraBlock
	}
	return *d.CryptoEnvelope
}

// ShouldReEncryptAcraStructToAcraBlock return true if should  re-encrypt data with AcraBlock
func (d defaultValues) ShouldReEncryptAcraStructToAcraBlock() bool {
	if d.ReEncryptToAcraBlock == nil {
		return true
	}
	return *d.ReEncryptToAcraBlock
}

type storeConfig struct {
	DatabaseSettings *databaseSettings `yaml:"database_settings"`
	Defaults         *defaultValues
	Schemas          []*tableSchema
}

// MapTableSchemaStore store schemas per table name
type MapTableSchemaStore struct {
	databaseSettings *databaseSettings
	schemas          map[string]*tableSchema
	globalMask       SettingMask
}

// NewMapTableSchemaStore return new MapTableSchemaStore
func NewMapTableSchemaStore() (*MapTableSchemaStore, error) {
	return &MapTableSchemaStore{schemas: make(map[string]*tableSchema)}, nil
}

// MapTableSchemaStoreFromConfig parse config and return MapTableSchemaStore with data from config
func MapTableSchemaStoreFromConfig(config []byte) (*MapTableSchemaStore, error) {
	storeConfig := &storeConfig{}
	if err := yaml.Unmarshal(config, &storeConfig); err != nil {
		return nil, err
	}
	if storeConfig.Defaults == nil {
		storeConfig.Defaults = &defaultValues{}
	}
	if storeConfig.Defaults != nil && storeConfig.Defaults.CryptoEnvelope != nil {
		if err := ValidateCryptoEnvelopeType(*storeConfig.Defaults.CryptoEnvelope); err != nil {
			return nil, err
		}
	}
	var mask SettingMask
	mapSchemas := make(map[string]*tableSchema, len(storeConfig.Schemas))
	for _, schema := range storeConfig.Schemas {
		for _, setting := range schema.EncryptionColumnSettings {
			setting.applyDefaults(*storeConfig.Defaults)
			if err := setting.Init(); err != nil {
				return nil, err
			}

			mask |= setting.settingMask
		}
		mapSchemas[schema.TableName] = schema
	}
	return &MapTableSchemaStore{
		databaseSettings: storeConfig.DatabaseSettings,
		schemas:          mapSchemas,
		globalMask:       mask,
	}, nil
}

// GetDatabaseSettings return struct with database-specific configuration
func (store *MapTableSchemaStore) GetDatabaseSettings() DatabaseSettings {
	// Create default set of values so GetDatabaseSettings() won't fail
	// if this section is missing in the config file or if the config
	// file was not specified at all and MapTableSchemaStoreFromConfig()
	// never executed
	if store.databaseSettings == nil {
		defaultMySQLCaseSensitiveTableID := false
		return &databaseSettings{
			MysqlSetting: mysqlSetting{
				CaseSensitiveTableIdentifiers: &defaultMySQLCaseSensitiveTableID,
			},
			PostgresqlSetting: postgresqlSetting{},
		}
	}

	return store.databaseSettings
}

// GetGlobalSettingsMask return OR of all masks of column settings
func (store *MapTableSchemaStore) GetGlobalSettingsMask() SettingMask {
	return store.globalMask
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
