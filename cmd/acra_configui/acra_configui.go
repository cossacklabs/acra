// Copyright 2018, Cossack Labs Limited
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
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/logging"
	"strings"
	"crypto/subtle"
	"encoding/base64"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var host *string
var port *int
var acraHost *string
var acraPort *int
var debug *bool
var staticPath *string
var authMode *string
var parsedTemplate *template.Template
var err error
var configParamsBytes []byte

var SERVICE_NAME = "acra_configui"
var DEFAULT_CONFIG_PATH = utils.GetConfigPathByName(SERVICE_NAME)

const (
	HTTP_TIMEOUT = 5
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

type ConfigAcraServer struct {
	ProxyHost         string `json:"host"`
	ProxyPort         int    `json:"port"`
	DbHost            string `json:"db_host"`
	DbPort            int    `json:"db_port"`
	ProxyCommandsPort int    `json:"commands_port"`
	Debug             bool   `json:"debug"`
	ScriptOnPoison    string `json:"poisonscript"`
	StopOnPoison      bool   `json:"poisonshutdown"`
	WithZone          bool   `json:"zonemode"`
}

func SubmitSettings(w http.ResponseWriter, r *http.Request) {
	log.Debugf("SubmitSettings request %v", r)
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
	var db_port, _ = strconv.Atoi(r.Form.Get("db_port"))
	var commands_port, _ = strconv.Atoi(r.Form.Get("commands_port"))
	var debug, _ = strconv.ParseBool(r.Form.Get("debug"))
	var zonemode, _ = strconv.ParseBool(r.Form.Get("zonemode"))
	var poisonshutdown, _ = strconv.ParseBool(r.Form.Get("poisonshutdown"))
	config := ConfigAcraServer{
		DbHost:            r.Form.Get("db_host"),
		DbPort:            db_port,
		ProxyCommandsPort: commands_port,
		Debug:             debug,
		ScriptOnPoison:    r.Form.Get("poisonscript"),
		StopOnPoison:      poisonshutdown,
		WithZone:          zonemode,
	}
	jsonToServer, err := json.Marshal(config)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantSetNewConfig).
			Errorln("/setConfig json.Marshal failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%v:%v/setConfig", *acraHost, *acraPort), bytes.NewBuffer(jsonToServer))
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
	tplPath := filepath.Join(staticPath, "index.html")
	tplPath, err = utils.AbsPath(tplPath)
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
	log.Debugf("Index request %v", r)
	w.Header().Set("Content-Security-Policy", "require-sri-for script style")

	// get current config
	var netClient = &http.Client{
		Timeout: time.Second * HTTP_TIMEOUT,
	}
	serverResponse, err := netClient.Get(fmt.Sprintf("http://%v:%v/getConfig", *acraHost, *acraPort))
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetCurrentConfig).
			Errorln("AcraServer API error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serverConfigDataJsonString, err := ioutil.ReadAll(serverResponse.Body)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantGetCurrentConfig).
			Errorln("Can't read configuration")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var serverConfigData ConfigAcraServer
	err = json.Unmarshal(serverConfigDataJsonString, &serverConfigData)
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

func BasicAuthHandler(handler http.HandlerFunc) http.HandlerFunc {
	var realm = "AcraConfigUI"

	return func(w http.ResponseWriter, r *http.Request) {
		if *authMode == "auth_on" ||
			(*authMode == "auth_off_local" && *host != "127.0.0.1" && *host != "localhost") {

			user, pass, basicOk := r.BasicAuth()

			if _, ok := authUsers[user]; !ok {
				log.Warningf("No user[%v] found for auth", user)
				basicOk = false
			}

			var newHash []byte
			var authUserData cmd.UserAuth
			var err error
			if basicOk {
				authUserData = authUsers[user]
				newHash, err = cmd.HashArgon2(pass, authUserData.Salt, authUserData.Argon2Params)
				if err != nil {
					log.WithError(err).Errorln("hashArgon2")
					basicOk = false
				}
			}
			if !basicOk || subtle.ConstantTimeCompare(newHash, authUserData.Hash) != 1 {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%v"`, realm))
				w.WriteHeader(401)
				w.Write([]byte("Unauthorised.\n"))
				return
			}
		}
		handler(w, r)
	}
}

func getAuthData() (err error) {
	authFieldsCount := 4
	argon2FieldsCount := 4
	var netClient = &http.Client{
		Timeout: time.Second * HTTP_TIMEOUT,
	}
	serverResponse, err := netClient.Get(fmt.Sprintf("http://%v:%v/getAuthData", *acraHost, *acraPort))
	if err != nil {
		log.WithError(err).Errorln("AcraServer api error")
		return err
	}
	if serverResponse.StatusCode != 200 {
		log.WithError(err).Errorf("AcraServer status: %v", serverResponse.Status)
		return err
	}
	authDataSting, err := ioutil.ReadAll(serverResponse.Body)
	line := 0
	for _, authString := range strings.Split(string(authDataSting), "\n") {
		authItem := strings.Split(authString, ":")
		line += 1
		if len(authItem) == authFieldsCount {
			decoded, err := base64.StdEncoding.DecodeString(string(authItem[3]))
			if err != nil {
				log.WithError(err).Errorf("line[%v] DecodeString, user: %v", line, authItem[0])
				continue
			}
			argon2P := strings.Split(authItem[2], ",")
			if len(authItem) != argon2FieldsCount {
				log.WithError(err).Errorln("line[%v] wrong number of argon2 params: got %v, expected %v", line, len(authItem), argon2FieldsCount)
				continue
			}
			Time, err := strconv.ParseUint(argon2P[0], 10, 32)
			if err != nil {
				log.WithError(err).Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Time", authItem[0])
				continue
			}
			Memory, err := strconv.ParseUint(argon2P[1], 10, 32)
			if err != nil {
				log.WithError(err).Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Memory", authItem[0])
				continue
			}
			Threads, err := strconv.ParseUint(argon2P[2], 10, 8)
			if err != nil {
				log.WithError(err).Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Threads", authItem[0])
				continue
			}
			Length, err := strconv.ParseUint(argon2P[3], 10, 32)
			if err != nil {
				log.WithError(err).Errorf("line[%v] argon2 strconv.ParseUint(%v), user: %v", line, "Length", authItem[0])
				continue
			}
			authUsers[authItem[0]] = cmd.UserAuth{Salt: authItem[1], Hash: decoded, Argon2Params: cmd.Argon2Params{
				Time:    uint32(Time),
				Memory:  uint32(Memory),
				Threads: uint8(Threads),
				Length:  uint32(Length),
			}}
		}
	}
	return
}

func main() {
	host = flag.String("host", cmd.DEFAULT_ACRA_CONFIGUI_HOST, "Host for configUI HTTP endpoint")
	port = flag.Int("port", cmd.DEFAULT_ACRA_CONFIGUI_PORT, "Port for configUI HTTP endpoint")
	loggingFormat := flag.String("logging_format", "plaintext", "Logging format: plaintext, json or CEF")
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)
	log.Infof("Starting service")
	acraHost = flag.String("acra_host", "localhost", "Host for Acraserver HTTP endpoint or proxy")
	acraPort = flag.Int("acra_port", cmd.DEFAULT_PROXY_API_PORT, "Port for Acraserver HTTP endpoint or proxy")
	staticPath = flag.String("static_path", cmd.DEFAULT_ACRA_CONFIGUI_STATIC, "Path to static content")
	debug = flag.Bool("d", false, "Turn on debug logging")
	authMode = flag.String("auth_mode", cmd.DEFAULT_ACRA_CONFIGUI_AUTH_MODE, "Mode for basic auth. Possible values: auth_on|auth_off_local|auth_off")

	err = cmd.Parse(DEFAULT_CONFIG_PATH)
	if err != nil {
		log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantReadServiceConfig).
			Errorln("Can't parse args")
		os.Exit(1)
	}

	// if log format was overridden
	logging.CustomizeLogging(*loggingFormat, SERVICE_NAME)

	log.Infof("Validating service configuration")

	if *debug {
		logging.SetLogLevel(logging.LOG_DEBUG)
	} else {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	}

	err = parseTemplate(*staticPath)
	if err != nil {
		os.Exit(1)
	}

	err = getAuthData()
	if err != nil {
		os.Exit(1)
	}

	configParamsBytes = []byte(AcraServerCofig)
	http.HandleFunc("/index.html", BasicAuthHandler(index))
	http.HandleFunc("/", BasicAuthHandler(index))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(*staticPath))))
	http.HandleFunc("/acraserver/submit_setting", BasicAuthHandler(SubmitSettings))
	log.Infof("AcraConfigUI is listening @ %s:%d with PID %d", *host, *port, os.Getpid())
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", *host, *port), nil)
	check(err)
}
