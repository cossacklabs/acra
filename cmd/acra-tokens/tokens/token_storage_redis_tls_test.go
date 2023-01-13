//go:build integration && redis && tls
// +build integration,redis,tls

package tokens

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/utils/tests"
)

func TestTokensStatusWithTLSRedis(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Expected no panics in command")
		}
	}()

	hostport := os.Getenv("TEST_REDIS_HOSTPORT")
	if hostport == "" {
		hostport = "localhost:6380"
	}
	password := os.Getenv("TEST_REDIS_PASSWORD")
	if password == "" {
		password = ""
	}

	dbNum := os.Getenv("TEST_REDIS_DB")
	if dbNum == "" {
		dbNum = "0"
	}

	flagSet := flag.NewFlagSet("status", flag.ContinueOnError)
	cmd.RegisterRedisTokenStoreParametersWithPrefix(flagSet, "", "")

	workingDirectory := tests.GetSourceRootDirectory(t)
	flagsToSet := map[string]string{
		"redis_host_port":                 hostport,
		"redis_password":                  password,
		"redis_db_tokens":                 dbNum,
		"redis_tls_enable":                "true",
		"redis_tls_client_ca":             filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"),
		"redis_tls_client_key":            filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.key"),
		"redis_tls_client_cert":           filepath.Join(workingDirectory, "tests/ssl/acra-writer/acra-writer.crt"),
		"redis_tls_crl_client_from_cert":  "ignore",
		"redis_tls_ocsp_client_from_cert": "ignore",
	}

	for flag, value := range flagsToSet {
		if err := flagSet.Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}

	statusSubCommand := &StatusSubcommand{
		flagSet: flagSet,
	}

	statusSubCommand.Execute()
}
