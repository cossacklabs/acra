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

type DatabaseConfig interface {
	GetMySQLCaseSensitiveTableID() bool
}

// databaseConfig stores database-specific configuration that can affect connection
// to the database, how SQL queries are processed and so on
type databaseConfig struct {
	// Should we consider unquoted table identifiers to be case-sensitive?
	MySQLCaseSensitiveTableID *bool `yaml:"mysql_case_sensitive_table_identifiers"`
}

// GetMySQLCaseSensitiveTableID returns true if Acra was configured to preserve
// case in unquoted table identifiers (names); only for MySQL
func (config *databaseConfig) GetMySQLCaseSensitiveTableID() bool {
	if config.MySQLCaseSensitiveTableID == nil {
		return false
	}

	return *config.MySQLCaseSensitiveTableID
}
