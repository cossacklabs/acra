// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"net/http"
	_ "net/http/pprof"
	"os"
)

// DEFAULT_CONFIG_PATH relative path to config which will be parsed as default
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName("acraserver")

func main() {
	dbHost := flag.String("db_host", "", "Host to db")
	dbPort := flag.Int("db_port", 5432, "Port to db")

	host := flag.String("host", cmd.DEFAULT_ACRA_HOST, "Host for AcraServer")
	port := flag.Int("port", cmd.DEFAULT_ACRA_PORT, "Port for AcraServer")
	commandsPort := flag.Int("commands_port", cmd.DEFAULT_ACRA_API_PORT, "Port for AcraServer for http api")

	keysDir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder from which will be loaded keys")

	hexFormat := flag.Bool("hex_bytea", false, "Hex format for Postgresql bytea data (default)")
	escapeFormat := flag.Bool("escape_bytea", false, "Escape format for Postgresql bytea data")

	serverId := flag.String("server_id", "acra_server", "Id that will be sent in secure session")

	verbose := flag.Bool("v", false, "Log to stdout")
	flag.Bool("wholecell", true, "Acrastruct will stored in whole data cell")
	injectedcell := flag.Bool("injectedcell", false, "Acrastruct may be injected into any place of data cell")

	debug := flag.Bool("d", false, "Turn on debug logging")
	debugServer := flag.Bool("ds", false, "Turn on http debug server")

	stopOnPoison := flag.Bool("poisonshutdown", false, "Stop on detecting poison record")
	scriptOnPoison := flag.String("poisonscript", "", "Execute script on detecting poison record")

	withZone := flag.Bool("zonemode", false, "Turn on zone mode")
	disableZoneApi := flag.Bool("disable_zone_api", false, "Disable zone http api")

	useTls := flag.Bool("tls", false, "Use tls")
	tlsKey := flag.String("tls_key", "", "Path to tls server key")
	tlsCert := flag.String("tls_cert", "", "Path to tls server certificate")
	noEncryption := flag.Bool("no_encryption", false, "Don't use encryption in transport")
	acraConnectionString := flag.String("connection_string", network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRA_HOST, cmd.DEFAULT_ACRA_PORT, ""), "Connection string like tcp://x.x.x.x:yyyy or unix:///path/to/socket")
	acraAPIConnectionString := flag.String("connection_api_string", network.BuildConnectionString(cmd.DEFAULT_ACRA_CONNECTION_PROTOCOL, cmd.DEFAULT_ACRA_HOST, cmd.DEFAULT_ACRA_API_PORT, ""), "Connection string for api like tcp://x.x.x.x:yyyy or unix:///path/to/socket")

	err := cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("Can't parse args", err))
		os.Exit(1)
	}

	cmd.ValidateClientId(*serverId)

	if *host != cmd.DEFAULT_ACRA_HOST || *port != cmd.DEFAULT_ACRA_PORT {
		*acraConnectionString = network.BuildConnectionString("tcp", *host, *port, "")
	}
	if *commandsPort != cmd.DEFAULT_ACRA_API_PORT {
		*acraConnectionString = network.BuildConnectionString("tcp", *host, *commandsPort, "")
	}

	if *debug {
		cmd.SetLogLevel(cmd.LOG_DEBUG)
	} else if *verbose {
		cmd.SetLogLevel(cmd.LOG_VERBOSE)
	} else {
		cmd.SetLogLevel(cmd.LOG_DISCARD)
	}
	if *dbHost == "" {
		fmt.Println("Error: you must specify db_host")
		flag.Usage()
		return
	}

	config := NewConfig()
	// now it's stub as default values
	config.SetStopOnPoison(*stopOnPoison)
	config.SetScriptOnPoison(*scriptOnPoison)
	config.SetWithZone(*withZone)
	config.SetDBHost(*dbHost)
	config.SetDBPort(*dbPort)
	config.SetProxyHost(*host)
	config.SetProxyPort(*port)
	config.SetProxyCommandsPort(*commandsPort)
	config.SetKeysDir(*keysDir)
	config.SetServerId([]byte(*serverId))
	config.SetAcraConnectionString(*acraConnectionString)
	config.SetAcraAPIConnectionString(*acraAPIConnectionString)
	config.SetWholeMatch(!(*injectedcell))
	if *hexFormat || !*escapeFormat {
		config.SetByteaFormat(HEX_BYTEA_FORMAT)
	} else {
		config.SetByteaFormat(ESCAPE_BYTEA_FORMAT)
	}

	keyStore, err := keystore.NewFilesystemKeyStore(*keysDir)
	if err != nil {
		log.Println("Error: can't initialize keystore")
		os.Exit(1)
	}
	if *useTls {
		log.Println("Use TLS transport wrapper")
		cer, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Println(err)
			return
		}
		config.ConnectionWrapper, err = network.NewTLSConnectionWrapper(&tls.Config{Certificates: []tls.Certificate{cer}})
		if err != nil {
			log.Println("Error: can't initialize tls connection wrapper")
			os.Exit(1)
		}
	} else if *noEncryption {
		log.Println("Use raw transport wrapper")
		config.ConnectionWrapper = &network.RawConnectionWrapper{ClientId: []byte(*serverId)}
	} else {
		log.Println("Use Secure Session transport wrapper")
		config.ConnectionWrapper, err = network.NewSecureSessionConnectionWrapper(keyStore)
		if err != nil {
			log.Println("Error: can't initialize secure session connection wrapper")
			os.Exit(1)
		}
	}

	server, err := NewServer(config)
	if err != nil {
		panic(err)
	}

	if *debugServer {
		//start http server for pprof
		go func() {
			err := http.ListenAndServe("127.0.0.1:6060", nil)
			if err != nil {
				log.Printf("Error: %v\n", utils.ErrorMessage("error from debug server", err))
			}
		}()
	}
	if *withZone && !*disableZoneApi {
		go server.StartCommands()
	}
	server.Start()
}
