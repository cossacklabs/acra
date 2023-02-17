package tests

import (
	"github.com/cossacklabs/acra/cmd/acra-server/common"
	"github.com/cossacklabs/acra/crypto"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/network"
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
)

func NewDefaultAcraServerConfig(t *testing.T) *common.Config {
	dbConfig := GetDatabaseConfig(t)
	serverConfig, err := common.NewConfig()
	assert.Nil(t, err)

	serverConfig.SetDBConnectionSettings("localhost", dbConfig.Port)
	if err = serverConfig.SetDatabaseType(false, true); err != nil {
		t.Fatal(err)
	}
	clientIDExtractor, err := network.NewDefaultTLSClientIDExtractor()
	assert.Nil(t, err)
	serverConfig.SetTLSClientIDExtractor(clientIDExtractor)
	serverConfig.ConnectionWrapper = &network.RawConnectionWrapper{ClientID: nil}
	serverConfig.SetUseClientIDFromCertificate(true)
	serverKeystore := GetNewDefaultKeystore(t)
	serverConfig.SetKeyStore(serverKeystore)
	return serverConfig
}

func NewAcraServer(t *testing.T, serverConfig *common.Config, proxyFactory base.ProxyFactory, port int) *common.SServer {
	serverConfig.SetAcraConnectionString("tcp://localhost:" + strconv.Itoa(port))
	err := crypto.InitRegistry(serverConfig.GetKeyStore())
	assert.Nil(t, err)
	errCh := make(chan os.Signal, 2)
	server, err := common.NewEEAcraServerMainComponent(serverConfig, proxyFactory, errCh, errCh)
	assert.Nil(t, err)
	return server
}
