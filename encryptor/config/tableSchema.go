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
	"errors"
	"gopkg.in/yaml.v2"
)

// TableSchemaStore interface to fetch schema for table
type TableSchemaStore interface {
	GetTableSchema(tableName string) *TableSchema
	IsEmpty() bool
}

type storeConfig struct {
	Schemas []*TableSchema
}

// MapTableSchemaStore store schemas per table name
type MapTableSchemaStore struct {
	schemas map[string]*TableSchema
}

// NewMapTableSchemaStore return new MapTableSchemaStore
func NewMapTableSchemaStore() (*MapTableSchemaStore, error) {
	return &MapTableSchemaStore{make(map[string]*TableSchema)}, nil
}

// ErrInvalidTokenType error for invalid value of token_type parameter
var ErrInvalidTokenType = errors.New("invalid token type")

// ErrInvalidPlainTextSide error for invalid value of plaintext_side parameter
var ErrInvalidPlainTextSide = errors.New("invalid plaintext_side")

// MapTableSchemaStoreFromConfig parse config and return MapTableSchemaStore with data from config
func MapTableSchemaStoreFromConfig(config []byte) (*MapTableSchemaStore, error) {
	storeConfig := &storeConfig{}
	if err := yaml.Unmarshal(config, &storeConfig); err != nil {
		return nil, err
	}
	mapSchemas := make(map[string]*TableSchema, len(storeConfig.Schemas))
	for _, schema := range storeConfig.Schemas {
		for _, setting := range schema.EncryptionColumnSettings {
			if setting.Tokenized {
				if !ValidateTokenType(setting.TokenType) {
					return nil, ErrInvalidTokenType
				}
			}
			if !ValidateMaskingParams(setting) {
				return nil, ErrInvalidPlainTextSide
			}
		}
		mapSchemas[schema.TableName] = schema
	}
	return &MapTableSchemaStore{mapSchemas}, nil
}

// GetTableSchema return table schema if exists otherwise nil
func (store *MapTableSchemaStore) GetTableSchema(tableName string) *TableSchema {
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

// ColumnEncryptionSetting describe how to encrypt column
type ColumnEncryptionSetting struct {
	Name                     string        `yaml:"column"`
	ClientID                 string        `yaml:"client_id"`
	ZoneID                   string        `yaml:"zone_id"`
	Searchable               bool          `yaml:"searchable"`
	Masking                  string        `yaml:"masking"`
	PartialPlaintextLenBytes int           `yaml:"plaintext_length"`
	PlaintextSide            PlainTextSide `yaml:"plaintext_side"`
	Tokenized                bool          `yaml:"tokenized"`
	ConsistentTokenization   bool          `yaml:"consistent_tokenization"`
	TokenType                TokenType     `yaml:"token_type"`
}

// PlainTextSide type used to configure side where will be left plaintext, and where masking pattern
type PlainTextSide string

// Set of constants used to set plaintext side in masking
const (
	PlainTextSideLeft  PlainTextSide = "left"
	PlainTextSideRight PlainTextSide = "right"
)

// ValidateMaskingParams return true if setting has valid configuration for masking
func ValidateMaskingParams(setting *ColumnEncryptionSetting) bool {
	if setting.Masking == "" {
		return true
	}
	if setting.PartialPlaintextLenBytes < 0 {
		return false
	}
	if setting.PlaintextSide != PlainTextSideRight && setting.PlaintextSide != PlainTextSideLeft {
		return false
	}
	return true
}

var supportedTokenValues = map[TokenType]bool{
	TokenTypeInt32:  true,
	TokenTypeInt64:  true,
	TokenTypeBytes:  true,
	TokenTypeString: true,
	TokenTypeEmail:  true,
}

// ValidateTokenType return true if value is supported TokenType
func ValidateTokenType(value TokenType) bool {
	_, ok := supportedTokenValues[value]
	return ok
}

// TokenType used for constants of supported TokenTypes for tokenizator
type TokenType string

// Set of constants with supported TokenType
const (
	TokenTypeInt32   TokenType = "int32"
	TokenTypeInt64   TokenType = "int64"
	TokenTypeString  TokenType = "str"
	TokenTypeBytes   TokenType = "bytes"
	TokenTypeEmail   TokenType = "email"
	defaultTokenType TokenType = TokenTypeBytes
)

var tokenTypeMap = map[TokenType]TokenType{
	TokenTypeEmail:  TokenTypeEmail,
	TokenTypeInt32:  TokenTypeInt32,
	TokenTypeInt64:  TokenTypeInt64,
	TokenTypeBytes:  TokenTypeBytes,
	TokenTypeString: TokenTypeString,
}

// IsSearchable return true if column should be searchable
func (s *ColumnEncryptionSetting) IsSearchable() bool {
	return s.Searchable
}

// IsTokenized return true if column should be searchable
func (s *ColumnEncryptionSetting) IsTokenized() bool {
	return s.Tokenized
}

// IsConsistentTokenization return true if tokens should be consistent
func (s *ColumnEncryptionSetting) IsConsistentTokenization() bool {
	return s.ConsistentTokenization
}

// GetTokenType return true if column should be searchable
func (s *ColumnEncryptionSetting) GetTokenType() TokenType {
	t, ok := tokenTypeMap[s.TokenType]
	if ok {
		return t
	}
	return defaultTokenType
}

// GetMaskingPattern return string which should be used instead AcraStruct
func (s *ColumnEncryptionSetting) GetMaskingPattern() string {
	return s.Masking
}

// GetPartialPlaintextLen return count of bytes which should be left untouched in masked value
func (s *ColumnEncryptionSetting) GetPartialPlaintextLen() int {
	return s.PartialPlaintextLenBytes
}

// IsEndMasking return true if value should be masked starting from left
func (s *ColumnEncryptionSetting) IsEndMasking() bool {
	return s.PlaintextSide == PlainTextSideLeft
}

// TableSchema store table schema and encryption settings per column
type TableSchema struct {
	TableName                string                     `yaml:"table"`
	Columns                  []string                   `yaml:"columns"`
	EncryptionColumnSettings []*ColumnEncryptionSetting `yaml:"encrypted"`
	mapEncryptedColumns      map[string]*ColumnEncryptionSetting
}

// initMap create map of columns to encrypt from array
func (schema *TableSchema) initMap() {
	mapEncryptedColumns := make(map[string]*ColumnEncryptionSetting)
	for _, column := range schema.EncryptionColumnSettings {
		mapEncryptedColumns[column.Name] = column
	}
	schema.mapEncryptedColumns = mapEncryptedColumns
}

// NeedToEncrypt return true if columnName should be encrypted by config
func (schema *TableSchema) NeedToEncrypt(columnName string) bool {
	if schema.mapEncryptedColumns == nil {
		schema.initMap()
	}
	_, ok := schema.mapEncryptedColumns[columnName]
	return ok
}

// GetColumnEncryptionSettings return setting or nil
func (schema *TableSchema) GetColumnEncryptionSettings(columnName string) *ColumnEncryptionSetting {
	if schema.mapEncryptedColumns == nil {
		schema.initMap()
	}
	return schema.mapEncryptedColumns[columnName]
}
