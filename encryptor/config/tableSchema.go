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
	common2 "github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/cossacklabs/acra/pseudonymization/common"
)

// Defaults default parameters that may be configured for whole config to allow omit them for specific columns
type Defaults interface {
	GetCryptoEnvelope() CryptoEnvelopeType
	ShouldReEncryptAcraStructToAcraBlock() bool
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

// ColumnEncryptionSetting describes how to encrypt a table column.
type ColumnEncryptionSetting interface {
	common.TokenSetting

	ColumnName() string
	ClientID() []byte
	ZoneID() []byte

	GetEncryptedDataType() common2.EncryptedType
	GetDefaultDataValue() *string

	// Searchable encryption
	IsSearchable() bool
	// Data masking
	GetMaskingPattern() string
	GetPartialPlaintextLen() int
	IsEndMasking() bool
	OnlyEncryption() bool

	Defaults
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
