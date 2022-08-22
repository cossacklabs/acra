package cmd

import (
	"os"
	"strconv"
	"testing"
)

// GetTestRedisOptions returns options configured with test env variables
// use this function for tests
func GetTestRedisOptions(t *testing.T) RedisOptions {
	hostport := os.Getenv("TEST_REDIS_HOSTPORT")
	if hostport == "" {
		hostport = "localhost:6379"
	}
	// default is empty
	password := os.Getenv("TEST_REDIS_PASSWORD")
	dbNum := os.Getenv("TEST_REDIS_DB")
	if dbNum == "" {
		dbNum = "0"
	}
	dbInt, err := strconv.ParseInt(dbNum, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return RedisOptions{DBKeys: int(dbInt), HostPort: hostport, Password: password}
}
