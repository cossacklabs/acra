/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bufio"
	"context"
	"go.opencensus.io/trace"
	"net"
	"net/http"

	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"

	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"syscall"

	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/zone"
	"github.com/cossacklabs/themis/gothemis/cell"
	"github.com/cossacklabs/themis/gothemis/keys"
)

// HTTP 500 response
const (
	Response500Error = "HTTP/1.1 500 Server error\r\n\r\n\r\n\r\n"
)

// ClientCommandsSession handles Secure Session for client commands API
type ClientCommandsSession struct {
	ClientSession
	Server   *SServer
	keystore keystore.KeyStore
}

// NewClientCommandsSession returns new ClientCommandsSession
func NewClientCommandsSession(keystorage keystore.KeyStore, config *Config, connection net.Conn) (*ClientCommandsSession, error) {
	clientSession, err := NewClientSession(context.Background(), keystorage, config, connection)
	if err != nil {
		return nil, err
	}
	return &ClientCommandsSession{ClientSession: *clientSession, keystore: keystorage}, nil

}

// ConnectToDb should not be called, because command session must not connect to any DB
func (clientSession *ClientCommandsSession) ConnectToDb() error {
	return errors.New("command session must not connect to any DB")
}

func (clientSession *ClientCommandsSession) close() {
	log.Debugln("Close acra-connector connection")
	err := clientSession.connection.Close()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantCloseConnection).
			Errorln("Error during closing connection to acra-connector")
	}
	log.Debugln("All connections closed")
}

// HandleSession gets, parses and executes each client HTTP request, writes response to the connection
func (clientSession *ClientCommandsSession) HandleSession() {
	_, requestSpan := trace.StartSpan(clientSession.ctx, "HandleSession")
	defer requestSpan.End()

	logger := logging.NewLoggerWithTrace(clientSession.ctx)
	reader := bufio.NewReader(clientSession.connection)
	req, err := http.ReadRequest(reader)
	// req = clientSession.connection.Write(*http.ResponseWriter)
	if err != nil {

		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			Warningln("Got new command request, but can't read it")
		clientSession.close()
		return
	}
	response := "HTTP/1.1 404 Not Found\r\n\r\nincorrect request\r\n\r\n"

	logger.Debugf("Incoming API request to %v", req.URL.Path)

	requestSpan.AddAttributes(trace.StringAttribute("http.url", req.URL.Path))

	switch req.URL.Path {
	case "/getNewZone":
		logger.Debugln("Got /getNewZone request")
		id, publicKey, err := clientSession.keystorage.GenerateZoneKey()
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGenerateZone).Errorln("Can't generate zone key")
		} else {
			zoneData, err := zone.ZoneDataToJSON(id, &keys.PublicKey{Value: publicKey})
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGenerateZone).WithError(err).Errorln("Can't create json with zone key")
			} else {
				logger.Debugln("Handled request correctly")
				response = fmt.Sprintf("HTTP/1.1 200 OK Found\r\n\r\n%s\r\n\r\n", string(zoneData))
			}
		}
	case "/resetKeyStorage":
		logger.Debugln("Got /resetKeyStorage request")
		clientSession.keystorage.Reset()
		response = "HTTP/1.1 200 OK Found\r\n\r\n"
		logger.Debugln("Cleared key storage cache")
	case "/loadAuthData":
		response = Response500Error
		key, err := clientSession.keystore.GetAuthKey(false)
		if err != nil {
			logger.WithError(err).Error("loadAuthData: keystore.GetAuthKey()")
			response = Response500Error
			break
		}
		authDataCrypted, err := getAuthDataFromFile(*authPath)
		if err != nil {
			logger.Warningf("%v\n", utils.ErrorMessage("loadAuthData: no auth data", err))
			response = Response500Error
			break
		}
		SecureCell := cell.New(key, cell.CELL_MODE_SEAL)
		authData, err := SecureCell.Unprotect(authDataCrypted, nil, nil)
		if err != nil {
			logger.WithError(err).Error("loadAuthData: SecureCell.Unprotect")

			break
		}
		response = fmt.Sprintf("HTTP/1.1 200 OK Found\r\n\r\n%s\r\n\r\n", authData)
	case "/getConfig":
		logger.Debugln("Got /getConfig request")
		jsonOutput, err := clientSession.config.ToJSON()
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				Warningln("Can't convert config to JSON")
			response = Response500Error
		} else {
			logger.Debugln("Handled request correctly")
			logger.Debugln(string(jsonOutput))
			response = fmt.Sprintf("HTTP/1.1 200 OK Found\r\n\r\n%s\r\n\r\n", string(jsonOutput))
		}
	case "/setConfig":
		logger.Debugln("Got /setConfig request")
		decoder := json.NewDecoder(req.Body)
		var configFromUI UIEditableConfig
		err = decoder.Decode(&configFromUI)
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				Warningln("Can't convert config from incoming")
			response = Response500Error
			return
		}
		// set config values
		flag.Set("db_host", configFromUI.DbHost)
		flag.Set("db_port", fmt.Sprintf("%v", configFromUI.DbPort))
		flag.Set("incoming_connection_api_port", fmt.Sprintf("%v", configFromUI.ConnectorAPIPort))
		flag.Set("d", fmt.Sprintf("%v", configFromUI.Debug))
		flag.Set("poison_run_script_file", fmt.Sprintf("%v", configFromUI.ScriptOnPoison))
		flag.Set("poison_shutdown_enable", fmt.Sprintf("%v", configFromUI.StopOnPoison))
		flag.Set("zonemode_enable", fmt.Sprintf("%v", configFromUI.WithZone))

		err = cmd.DumpConfig(clientSession.Server.config.GetConfigPath(), ServiceName, false)
		if err != nil {
			logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantDumpConfig).
				Errorln("DumpConfig failed")
			response = Response500Error
			return

		}
		logger.Infoln("Handled request correctly, restarting server")
		clientSession.Server.restartSignalsChannel <- syscall.SIGHUP
	default:
		requestSpan.AddAttributes(trace.StringAttribute("http.url", "undefined"))
	}

	_, err = clientSession.connection.Write([]byte(response))
	if err != nil {
		logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).Errorln("Can't send data with secure session to acra-connector")
		return
	}
	clientSession.close()
}
