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
	// GetTableSchema returns schema for given table if configured, or nil otherwise.
	GetTableSchema(tableName string) TableSchema
	GetGlobalSettingsMask() SettingMask
}

// databaseConfig stores database-specific configuration that can affect connection
// to the database, how SQL queries are processed and so on
type databaseConfig struct {
	// Should we consider unquoted table identifiers to be case-sensitive?
	MySQLCaseSensitiveID *bool `yaml:"mysql_case_sensitive_identifiers"`
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
	DatabaseConfig *databaseConfig
	Defaults       *defaultValues
	Schemas        []*tableSchema
}

// MapTableSchemaStore store schemas per table name
type MapTableSchemaStore struct {
	schemas    map[string]*tableSchema
	globalMask SettingMask
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
	return &MapTableSchemaStore{schemas: mapSchemas, globalMask: mask}, nil
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
