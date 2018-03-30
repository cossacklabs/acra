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
	"bufio"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"

	"errors"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/keys"
	"fmt"
	"encoding/json"
	"syscall"
	"github.com/cossacklabs/acra/cmd"
	"flag"
)

type ClientCommandsSession struct {
	ClientSession
	Server *SServer
}

func NewClientCommandsSession(keystorage keystore.KeyStore, config *Config, connection net.Conn) (*ClientCommandsSession, error) {
	clientSession, err := NewClientSession(keystorage, config, connection)
	if err != nil {
		return nil, err
	}
	return &ClientCommandsSession{ClientSession: *clientSession}, nil

}

func (clientSession *ClientCommandsSession) ConnectToDb() error {
	return errors.New("command session must not connect to any DB")
}

func (clientSession *ClientCommandsSession) close() {
	log.Debugln("Close acraproxy connection")
	err := clientSession.connection.Close()
	if err != nil {
		log.WithError(err).Errorln("Error during closing connection to acraproxy")
	}
	log.Debugln("All connections closed")
}

func (clientSession *ClientCommandsSession) HandleSession() {
	reader := bufio.NewReader(clientSession.connection)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.WithError(err).Warningln("Got new command request, but can't read it")
		clientSession.close()
		return
	}
	response := "HTTP/1.1 404 Not Found\r\n\r\nincorrect request\r\n\r\n"

	log.Debugln(req.URL.Path)

	switch req.URL.Path {
	case "/getNewZone":
		log.Debugln("Got /getNewZone request")
		id, publicKey, err := clientSession.keystorage.GenerateZoneKey()
		if err == nil {
			zoneData, err := zone.ZoneDataToJson(id, &keys.PublicKey{Value: publicKey})
			if err == nil {
				log.Debugln("Handled request correctly")
				response = fmt.Sprintf("HTTP/1.1 200 OK Found\r\n\r\n%s\r\n\r\n", string(zoneData))
			}
		}
	case "/resetKeyStorage":
		log.Debugln("Got /resetKeyStorage request")
		clientSession.keystorage.Reset()
		response = "HTTP/1.1 200 OK Found\r\n\r\n"
		log.Debugln("Cleared key storage cache")
	case "/getConfig":
		log.Debugln("Got /getConfig request")
		jsonOutput, err := clientSession.config.ToJson()
		if err != nil {
			log.WithError(err).Warningln("Can't convert config to JSON")
			response = "HTTP/1.1 500 Server error\r\n\r\n\r\n\r\n"
		} else {
			log.Debugln("Handled request correctly")
			log.Debugln(string(jsonOutput))
			response = fmt.Sprintf("HTTP/1.1 200 OK Found\r\n\r\n%s\r\n\r\n", string(jsonOutput))
		}
	case "/setConfig":
		log.Debugln("Got /setConfig request")
		decoder := json.NewDecoder(req.Body)
		var configFromUI UIEditableConfig
		err := decoder.Decode(&configFromUI)
		if err != nil {
			log.WithError(err).Warningln("Can't convert config from incoming")
			response = "HTTP/1.1 500 Server error\r\n\r\n\r\n\r\n"
			return
		}
		// set config values
		flag.Set("db_host", configFromUI.DbHost)
		flag.Set("db_port", fmt.Sprintf("%v", configFromUI.DbPort))
		flag.Set("commands_port", fmt.Sprintf("%v", configFromUI.ProxyCommandsPort))
		flag.Set("d", fmt.Sprintf("%v", configFromUI.Debug))
		flag.Set("poisonscript", fmt.Sprintf("%v", configFromUI.ScriptOnPoison))
		flag.Set("poisonshutdown", fmt.Sprintf("%v", configFromUI.StopOnPoison))
		flag.Set("zonemode", fmt.Sprintf("%v", configFromUI.WithZone))

		err = cmd.DumpConfig(clientSession.Server.config.GetConfigPath(), false)
		if err != nil {
			log.WithError(err).Errorln("DumpConfig failed")
			response = "HTTP/1.1 500 Server error\r\n\r\n\r\n\r\n"
			return

		}
		log.Debugln("Handled request correctly, restarting server")
		clientSession.Server.restartSignalsChannel <- syscall.SIGHUP
	}

	_, err = clientSession.connection.Write([]byte(response))
	if err != nil {
		log.WithError(err).Errorln("Can't send data with secure session to acraproxy")
		return
	}
	clientSession.close()
}
