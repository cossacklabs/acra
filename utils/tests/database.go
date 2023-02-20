package tests

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
)

// DatabaseConfig stores configuration for test database
type DatabaseConfig struct {
	DBHost, Database, User, Password string
	Port                             int
}

// GetDatabaseConfig returns DatabaseConfig for integration tests configured with env variables or default values used
// for tests/test.py
func GetDatabaseConfig(t *testing.T) DatabaseConfig {
	var ok bool
	config := DatabaseConfig{}
	config.DBHost, ok = os.LookupEnv("TEST_DB_HOST")
	if !ok {
		config.DBHost = "localhost"
	}
	dbPortStr, ok := os.LookupEnv("TEST_DB_PORT")
	if ok {
		dbPort, err := strconv.Atoi(dbPortStr)
		assert.Nil(t, err)
		config.Port = dbPort
	} else {
		config.Port = 5432
	}
	config.Database, ok = os.LookupEnv("TEST_DB_NAME")
	if !ok {
		config.Database = "test"
	}
	config.User, ok = os.LookupEnv("TEST_DB_USER")
	if !ok {
		config.User = "test"
	}
	config.Password, ok = os.LookupEnv("TEST_DB_USER_PASSWORD")
	if !ok {
		config.Password = "test"
	}
	CheckConnection(t, fmt.Sprintf("%s:%d", config.DBHost, config.Port))
	return config
}
