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
	"bytes"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/poison"
	"github.com/cossacklabs/acra/utils"
	"github.com/vharitonsky/iniflags"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

const (
	DEFAULT_CONFIG_PATH = "configs/acraserver.conf"
)

var DEBUG_PREFIX = []byte("Debug: ")

type NotDebugWriter struct {
	writer io.Writer
}

func NewNotDebugWriter(writer io.Writer) *NotDebugWriter {
	return &NotDebugWriter{writer: writer}
}
func (wr *NotDebugWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, DEBUG_PREFIX) {
		return 0, nil
	}
	return wr.writer.Write(p)
}

func main() {
	db_host := flag.String("db_host", "", "Host to db")
	db_port := flag.Int("db_port", 5432, "Port to db")

	host := flag.String("host", "0.0.0.0", "Host for AcraServer")
	port := flag.Int("port", 9393, "Port for AcraServer")
	commands_port := flag.Int("commands_port", 9090, "Port for AcraServer for http api")

	keys_dir := flag.String("keys_dir", keystore.DEFAULT_KEY_DIR_SHORT, "Folder for keys")

	poison_key_path := flag.String("poison_key", poison.DEFAULT_POISON_KEY_PATH, "Path to file with poison key")

	hex_format := flag.Bool("hex_bytea", false, "Hex format for Postgresql bytea data (default)")
	escape_format := flag.Bool("escape_bytea", false, "Escape format for Postgresql bytea data")

	server_id := flag.String("server_id", "acra_server", "Id that will be sent in secure session")

	verbose := flag.Bool("v", false, "Log to stdout")
	flag.Bool("wholecell", true, "Acrastruct will stored in whole data cell")
	injectedcell := flag.Bool("injectedcell", false, "Acrastruct may be injected into any place of data cell")

	debug := flag.Bool("d", false, "Turn on debug logging")
	debug_server := flag.Bool("ds", false, "Turn on http debug server")

	stop_on_poison := flag.Bool("poisonshutdown", false, "Stop on detecting poison record")
	script_on_poison := flag.String("poisonscript", "", "Execute script on detecting poison record")

	with_zone := flag.Bool("zonemode", false, "Turn on zone mode")
	disable_zone_api := flag.Bool("disable_zone_api", false, "Disable zone http api")

	exists, err := utils.FileExists(DEFAULT_CONFIG_PATH)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't check is exists config file", err))
		os.Exit(1)
	}
	if exists {
		iniflags.SetConfigFile(DEFAULT_CONFIG_PATH)
	}
	iniflags.Parse()

	if *debug {
		log.SetOutput(os.Stdout)
	} else if *verbose {
		log.SetOutput(NewNotDebugWriter(os.Stdout))
	} else {
		log.SetOutput(ioutil.Discard)
	}
	if *db_host == "" {
		fmt.Println("Error: you must specify db_host")
		flag.Usage()
		return
	}

	poison_key, err := poison.GetOrCreatePoisonKey(*poison_key_path)
	if err != nil {
		fmt.Printf("Error: %v\n", utils.ErrorMessage("can't read poison key", err))
		os.Exit(1)
	}

	config := NewConfig()
	// now it's stub as default values
	config.SetStopOnPoison(*stop_on_poison)
	config.SetScriptOnPoison(*script_on_poison)
	config.SetWithZone(*with_zone)
	config.SetPoisonKey(poison_key)
	config.SetDBHost(*db_host)
	config.SetDBPort(*db_port)
	config.SetProxyHost(*host)
	config.SetProxyPort(*port)
	config.SetProxyCommandsPort(*commands_port)
	config.SetKeysDir(*keys_dir)
	config.SetServerId([]byte(*server_id))
	config.SetWholeMatch(!(*injectedcell))
	if *hex_format || !*escape_format {
		config.SetByteaFormat(HEX_BYTEA_FORMAT)
	} else {
		config.SetByteaFormat(ESCAPE_BYTEA_FORMAT)
	}

	server, err := NewServer(config)
	if err != nil {
		panic(err)
	}

	if *debug_server {
		//start http server for pprof
		go func() {
			err := http.ListenAndServe("127.0.0.1:6060", nil)
			if err != nil {
				log.Printf("Error: %v\n", utils.ErrorMessage("error from debug server", err))
			}
		}()
	}
	if *with_zone && !*disable_zone_api {
		go server.StartCommands()
	}
	server.Start()
}
