package tests

import (
	"crypto/tls"
	"fmt"
	"github.com/cossacklabs/acra/network"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func GetDefaultPeerTLSConfig(t *testing.T, peer string) *tls.Config {
	workingDirectory := GetSourceRootDirectory(t)
	tlsConfig, err := network.NewTLSConfig("localhost",
		filepath.Join(workingDirectory, "tests/ssl/ca/ca.crt"),
		filepath.Join(workingDirectory, fmt.Sprintf("tests/ssl/%s/%s.key", peer, peer)),
		filepath.Join(workingDirectory, fmt.Sprintf("tests/ssl/%s/%s.crt", peer, peer)),
		1, nil)
	assert.Nil(t, err)
	return tlsConfig
}
