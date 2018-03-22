package main

import (
	"io/ioutil"
	"html/template"
	"net/http"
	"path/filepath"
	"gopkg.in/yaml.v2"
	"time"
	"encoding/json"
	"strconv"
	"bytes"
	"os"
	"fmt"
	"flag"
	log "github.com/sirupsen/logrus"
	"github.com/cossacklabs/acra/utils"
	"github.com/cossacklabs/acra/logging"
)

var acraHost *string
var acraPort *int
var debug *bool

func check(e error) {
	if e != nil {
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
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.WithError(err).Errorln("Request parsing failed")
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
		log.WithError(err).Errorln("/setConfig json.Marshal failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%v:%v/setConfig", *acraHost, *acraPort), bytes.NewBuffer(jsonToServer))
	if err != nil {
		log.WithError(err).Errorln("/setConfig http.NewRequest failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.WithError(err).Errorln("/setConfig client.Do failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonToServer)
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "require-sri-for script style")
	parsedTemplate, _ := template.ParseFiles(filepath.Join("static", "index.html"))
	var outConfigParams configParamsYAML
	configParamsYAML, err := ioutil.ReadFile("acraserver_config_vars.yaml")
	check(err)

	// get current config
	var netClient = &http.Client{
		Timeout: time.Second * 5,
	}
	serverResponse, err := netClient.Get(fmt.Sprintf("http://%v:%v/getConfig", *acraHost, *acraPort))
	if err != nil {
		log.WithError(err).Errorln("AcraServer api error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	serverConfigDataJsonString, err := ioutil.ReadAll(serverResponse.Body)
	if err != nil {
		log.Fatal(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var serverConfigData ConfigAcraServer
	err = json.Unmarshal(serverConfigDataJsonString, &serverConfigData)
	if err != nil {
		log.WithError(err).Errorln("json.Unmarshal error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// end get current config

	err = yaml.Unmarshal(configParamsYAML, &outConfigParams)
	if err != nil {
		log.Errorf("%v", utils.ErrorMessage("yaml.Unmarshal error", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res, err := json.Marshal(outConfigParams)
	if err != nil {
		log.Errorf("%v", utils.ErrorMessage("json.Marshal error", err))
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

func main() {
	port := flag.Int("port", 8000, "Port for configUI HTTP endpoint")
	acraHost = flag.String("acraHost", "localhost", "Host for Acraserver HTTP endpoint or proxy")
	acraPort = flag.Int("acraPort", 9292, "Port for Acraserver HTTP endpoint or proxy")
	debug = flag.Bool("d", false, "Turn on debug logging")
	flag.Parse()

	if *debug {
		logging.SetLogLevel(logging.LOG_DEBUG)
	} else {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	}

	http.HandleFunc("/index.html", index)
	http.HandleFunc("/", index)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.HandleFunc("/acraserver/submit_setting", SubmitSettings)
	log.Info(fmt.Sprintf("AcraConfigUI is listening @ :%d with PID %d", *port, os.Getpid()))
	err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	check(err)
}
