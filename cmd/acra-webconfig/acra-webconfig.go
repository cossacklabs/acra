/*
Copyright 2018, Cossack Labs Limited

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

// Package main is entry point for AcraWebConfig service.AcraWebConfig is a lightweight HTTP web server for managing
// AcraServer's certain configuration options. AcraWebConfig uses HTTP API requests to get data from AcraServer
// and to change its settings. To provide additional security, AcraWebConfig uses basic authentication.
// Users/passwords are stored in an encrypted file and are managed by AcraAuthmanager utility.
//
// https://github.com/cossacklabs/acra/wiki/AcraWebConfig
package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var host *string
var port *int
var destinationHost *string
var destinationPort *int
var debug *bool
var staticPath *string
var authMode *string
var parsedTemplate *template.Template
var configParamsBytes []byte

// Constants used by AcraWebconfig
var (
	ServiceName       = "acra-webconfig"
	DefaultConfigPath = utils.GetConfigPathByName(ServiceName)
)

// ErrGetAuthDataFromAcraServer any error during loading AcraWebconfig
var ErrGetAuthDataFromAcraServer = errors.New("wrong status for loadAuthData")

// Connection timeout secs
const (
	HTTPTimeout = 5
)

// Argon2 parameters
const (
	LineSeparator = "\n"

	AuthFieldSeparator  = ":"
	AuthFieldCount      = 4
	AuthUsernameIDX     = 0
	AuthSaltIDX         = 1
	AuthArgon2ParamsIDX = 2
	AuthHashIDX         = 3

	Argon2ParamSeparator = ","
	Argon2ParamCount     = 4
	Argon2TimeIDX        = 0
	Argon2MemoryIDX      = 1
	Argon2ThreadsIDX     = 2
	Argon2LengthIDX      = 3

	Argon2TimeInt    = 32
	Argon2MemoryInt  = 32
	Argon2ThreadsInt = 8
	Argon2LengthInt  = 32

	UIntBase = 10
)

var authUsers = make(map[string]cmd.UserAuth)

func check(e error) {
	if e != nil {
		log.Error(e)
		panic(e)
	}
}

type paramItem struct {
	Name      string   `yaml:"name" json:"name"`
	Title     string   `yaml:"title" json:"title"`
	ValueType string   `yaml:"value_type" json:"value_type"`
	InputType string   `yaml:"input_type" json:"input_type"`
	Values    []string `yaml:"values,flow" json:"values,flow"`
	Labels    []string `yaml:"labels,flow" json:"labels,flow"`
}

type configParamsYAML struct {
	Config []paramItem
}

var outConfigParams configParamsYAML

// ConfigAcraServer stores configuration for AcraWebconfig and its json representation
type ConfigAcraServer struct {
	ConnectorHost    string `json:"incoming_connection_host"`
	ConnectorPort    int    `json:"incoming_connection_port"`
	DbHost           string `json:"db_host"`
	DbPort           int    `json:"db_port"`
	ConnectorAPIPort int    `json:"incoming_connection_api_port"`
	Debug            bool   `json:"debug"`
	ScriptOnPoison   string `json:"poison_run_script_file"`
	StopOnPoison     bool   `json:"poison_shutdown_enable"`
	WithZone         bool   `json:"zonemode_enable"`
}

// SubmitSettings updates AcraServer configuration from HTTP request
func SubmitSettings(w http.ResponseWriter, r *http.Request) {
	log.Debugln("SubmitSettings request")
	if r.Method != "POST" {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorRequestMethodNotAllowed).
			Errorln("Invalid request method")
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseRequestData).
			Errorln("Request parsing failed")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var dbPort, _ = strconv.Atoi(r.Form.Get("db_port"))
	var APIPort, _ = strconv.Atoi(r.Form.Get("incoming_connection_api_port"))
	var debug, _ = strconv.ParseBool(r.Form.Get("debug"))
	var zoneModeEnable, _ = strconv.ParseBool(r.Form.Get("zonemode_enable"))
	var poisonShutdownEnable, _ = strconv.ParseBool(r.Form.Get("poison_shutdown_enable"))
	config := ConfigAcraServer{
		DbHost:           r.Form.Get("db_host"),
		DbPort:           dbPort,
		ConnectorAPIPort: APIPort,
		Debug:            debug,
		ScriptOnPoison:   r.Form.Get("poison_run_script_file"),
		StopOnPoison:     poisonShutdownEnable,
		WithZone:         zoneModeEnable,
	}
	jsonToServer, err := json.Marshal(config)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantSetNewConfig).
			Errorln("/setConfig json.Marshal failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%v:%v/setConfig", *destinationHost, *destinationPort), bytes.NewBuffer(jsonToServer))
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantSetNewConfig).
			Errorln("/setConfig http.NewRequest failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantSetNewConfig).
			Errorln("/setConfig client.Do failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonToServer)
}

func parseTemplate(staticPath string) (err error) {
	log.Infof("Parsing template")
	tplPath := filepath.Join(staticPath, "index.html")
	tplPath, err = filepath.Abs(tplPath)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadTemplate).
			Errorf("No template file[%v]", tplPath)
		return err
	}

	parsedTemplate, err = template.ParseFiles(tplPath)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadTemplate).
			Errorf("Error while parsing template - %v", tplPath)
		return err
	}

	return nil
}

func index(w http.ResponseWriter, r *http.Request) {
	log.Debugln("Index request")
	w.Header().Set("Content-Security-Policy", "require-sri-for script style")

	// get current config
	var netClient = &http.Client{
		Timeout: time.Second * HTTPTimeout,
	}
	serverResponse, err := netClient.Get(fmt.Sprintf("http://%v:%v/getConfig", *destinationHost, *destinationPort))
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetCurrentConfig).
			Errorln("AcraServer API error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serverConfigDataJSONString, err := ioutil.ReadAll(serverResponse.Body)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetCurrentConfig).
			Errorln("Can't read configuration")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var serverConfigData ConfigAcraServer
	err = json.Unmarshal(serverConfigDataJSONString, &serverConfigData)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetCurrentConfig).
			Errorln("Can't unmarshal server config params")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// end get current config

	err = yaml.Unmarshal(configParamsBytes, &outConfigParams)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetCurrentConfig).
			Errorln("Can't unmarshal config params")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res, err := json.Marshal(outConfigParams)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetCurrentConfig).
			Errorln("Can't marshal config params")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	parsedTemplate.Execute(w, struct {
		ConfigParams string
		ConfigAcraServer
	}{
		string(res),
		serverConfigData,
	})
}

// basicAuthHandler check if user is authenticated to access AcraWebconfig page
func basicAuthHandler(handler http.HandlerFunc) http.HandlerFunc {
	var realm = "AcraWebConfig"

	return func(w http.ResponseWriter, r *http.Request) {
		if *authMode == "auth_on" ||
			(*authMode == "auth_off_local" && *host != "127.0.0.1" && *host != "localhost") {

			user, pass, basicOk := r.BasicAuth()

			if _, ok := authUsers[user]; !ok {
				log.Warningf("BasicAuth: unknown user '%v'", user)
				basicOk = false
			}

			var newHash []byte
			var authUserData cmd.UserAuth
			var err error
			if basicOk {
				authUserData = authUsers[user]
				newHash, err = cmd.HashArgon2(pass, authUserData.Salt, authUserData.Argon2Params)
				if err != nil {
					log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantHashPassword).
						Error("Error while hashing user password")
					basicOk = false
				}
			}
			if !basicOk || subtle.ConstantTimeCompare(newHash, authUserData.Hash) != 1 {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%v"`, realm))
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
				return
			}
		}
		handler(w, r)
	}
}

func parseArgon2Params(authDataSting []byte) {
	line := 0
	for _, authString := range strings.Split(string(authDataSting), LineSeparator) {
		authItem := strings.Split(authString, AuthFieldSeparator)
		line++
		if len(authItem) == AuthFieldCount {
			decoded, err := base64.StdEncoding.DecodeString(string(authItem[AuthHashIDX]))
			if err != nil {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseAuthData).WithError(err).Errorf("line[%v] DecodeString, user: %v", line, authItem[AuthUsernameIDX])
				continue
			}
			argon2P := strings.Split(authItem[AuthArgon2ParamsIDX], Argon2ParamSeparator)
			if len(authItem) != Argon2ParamCount {
				log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseAuthData).
					Errorf("line[%v] wrong number of argon2 params: got %v, expected %v", line, len(authItem), Argon2ParamCount)
				continue
			}
			Time, err := strconv.ParseUint(argon2P[Argon2TimeIDX], UIntBase, Argon2TimeInt)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseAuthData).
					Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Time", authItem[AuthUsernameIDX])
				continue
			}
			Memory, err := strconv.ParseUint(argon2P[Argon2MemoryIDX], UIntBase, Argon2MemoryInt)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseAuthData).
					Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Memory", authItem[AuthUsernameIDX])
				continue
			}
			Threads, err := strconv.ParseUint(argon2P[Argon2ThreadsIDX], UIntBase, Argon2ThreadsInt)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseAuthData).
					Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Threads", authItem[AuthUsernameIDX])
				continue
			}
			Length, err := strconv.ParseUint(argon2P[Argon2LengthIDX], UIntBase, Argon2LengthInt)
			if err != nil {
				log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseAuthData).
					Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Length", authItem[AuthUsernameIDX])
				continue
			}
			authUsers[authItem[AuthUsernameIDX]] = cmd.UserAuth{Salt: authItem[AuthSaltIDX], Hash: decoded, Argon2Params: cmd.Argon2Params{
				Time:    uint32(Time),
				Memory:  uint32(Memory),
				Threads: uint8(Threads),
				Length:  uint32(Length),
			}}
		}
	}
}

func loadAuthData() (err error) {
	var netClient = &http.Client{
		Timeout: time.Second * HTTPTimeout,
	}
	serverResponse, err := netClient.Get(fmt.Sprintf("http://%v:%v/loadAuthData", *destinationHost, *destinationPort))
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetAuthData).
			Error("Error while getting auth data from AcraServer")
		return err
	}
	defer serverResponse.Body.Close()
	if serverResponse.StatusCode != http.StatusOK {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetAuthData).
			Errorf("Error while getting auth data from AcraServer, response status: %v", serverResponse.Status)
		return ErrGetAuthDataFromAcraServer
	}
	authDataSting, err := ioutil.ReadAll(serverResponse.Body)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantParseAuthData).
			Error("Error while reading auth data")
		return err
	}
	parseArgon2Params(authDataSting)
	return
}

func main() {
	host = flag.String("incoming_connection_host", cmd.DefaultWebConfigHost, "Host for AcraWebconfig HTTP endpoint")
	port = flag.Int("incoming_connection_port", cmd.DefaultWebConfigPort, "Port for AcraWebconfig HTTP endpoint")
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	log.Infof("Starting service %v [pid=%v]", ServiceName, os.Getpid())
	destinationHost = flag.String("destination_host", "localhost", "Host for AcraServer HTTP endpoint or AcraConnector")
	destinationPort = flag.Int("destination_port", cmd.DefaultAcraConnectorAPIPort, "Port for AcraServer HTTP endpoint or AcraConnector")
	staticPath = flag.String("static_path", cmd.DefaultWebConfigStatic, "Path to static content")
	debug = flag.Bool("d", false, "Turn on debug logging")
	authMode = flag.String("http_auth_mode", cmd.DefaultWebConfigAuthMode, "Mode for basic auth. Possible values: auth_on|auth_off_local|auth_off")
	err := cmd.Parse(DefaultConfigPath, ServiceName)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	logging.Customize().SetFormat(*loggingFormat).SetServiceName(ServiceName).Complete()
	log.Infof("Validating service configuration")

	if *debug {
		logging.SetLogLevel(logging.LogDebug)
	} else {
		logging.SetLogLevel(logging.LogVerbose)
	}

	err = parseTemplate(*staticPath)
	if err != nil {
		os.Exit(1)
	}

	if *authMode == "auth_off" {
		log.Warningf("HTTP Basic Auth is turned off")
	} else {
		log.Infof("HTTP Basic Auth mode: %v", *authMode)
		err = loadAuthData()
		if err != nil {
			os.Exit(1)
		}
	}

	configParamsBytes = []byte(AcraServerConfig)
	http.HandleFunc("/index.html", basicAuthHandler(index))
	http.HandleFunc("/", basicAuthHandler(index))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(*staticPath))))
	http.HandleFunc("/acra-server/submit_setting", basicAuthHandler(SubmitSettings))
	log.Infof("AcraWebconfig is listening @ %s:%d with PID %d", *host, *port, os.Getpid())
	server := &http.Server{ReadTimeout: network.DefaultNetworkTimeout, WriteTimeout: network.DefaultNetworkTimeout, Addr: fmt.Sprintf("%s:%d", *host, *port)}
	err = server.ListenAndServe()
	check(err)
}
