/*
 * Copyright 2022, Cossack Labs Limited
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

// DatabaseSettings stores different database-specific configuration options
type DatabaseSettings interface {
	GetMySQLDatabaseSettings() MySQLDatabaseSettings
	GetPostgreSQLDatabaseSettings() PostgreSQLDatabaseSettings
}

// MySQLDatabaseSettings stores MySQL-specific configuration
type MySQLDatabaseSettings interface {
	GetCaseSensitiveTableIdentifiers() bool
}

// PostgreSQLDatabaseSettings stores PostgreSQL-specific configuration
type PostgreSQLDatabaseSettings interface{}

type mysqlSetting struct {
	// Should we consider table identifiers to be case-sensitive?
	CaseSensitiveTableIdentifiers *bool `yaml:"case_sensitive_table_identifiers"`
}

// GetCaseSensitiveTableIdentifiers returns true if Acra was configured to preserve
// case in table identifiers (names)
func (settings *mysqlSetting) GetCaseSensitiveTableIdentifiers() bool {
	if settings.CaseSensitiveTableIdentifiers == nil {
		return false
	}

	return *settings.CaseSensitiveTableIdentifiers
}

type postgresqlSetting struct{}

// databaseSettings stores database-specific configuration that can affect connection
// to the database, how SQL queries are processed and so on
type databaseSettings struct {
	mysqlSetting      mysqlSetting      `yaml:"mysql"`
	postgresqlSetting postgresqlSetting `yaml:"postgresql"`
}

func (settings *databaseSettings) GetMySQLDatabaseSettings() MySQLDatabaseSettings {
	return &settings.mysqlSetting
}

func (settings *databaseSettings) GetPostgreSQLDatabaseSettings() PostgreSQLDatabaseSettings {
	return &settings.postgresqlSetting
}
