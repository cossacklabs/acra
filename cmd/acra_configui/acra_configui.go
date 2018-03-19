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
	"github.com/cossacklabs/acra/cmd"
	"syscall"
	"github.com/cossacklabs/acra/logging"
)

var acraHost *string
var acraPort *int
var debug *bool
var staticPath *string
var parsedTemplate *template.Template
var CONFIG_PATH = utils.GetConfigPathByName("acraserver_config_vars")
var err error
var configParamsBytes []byte

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

func parseTemplate() {
	tplPath := fmt.Sprintf(filepath.Join(*staticPath, "index.html"))
	tplPath, err = utils.AbsPath(tplPath)
	if err != nil {
		log.WithError(err).Errorf("no config file[%v]", tplPath)
	}

	parsedTemplate, err = template.ParseFiles(tplPath)
	if err != nil {
		log.WithError(err).Errorf("err while parsing template - %v", tplPath)
		syscall.Exit(1)
	}
}

func parseConfig() []byte {
	configPath, err_ := utils.AbsPath(fmt.Sprintf("./%s", CONFIG_PATH))
	if err_ != nil {
		log.WithError(err).Errorf("no config file[%v]", configPath)
		syscall.Exit(1)
	}
	configParamsBytes, err = ioutil.ReadFile(configPath)
	if err != nil {
		log.WithError(err).Errorf("reading config[%v] failed", configPath)
		syscall.Exit(1)
	}
	return configParamsBytes
}

func index(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Index request %v", r)
	w.Header().Set("Content-Security-Policy", "require-sri-for script style")

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

	err = yaml.Unmarshal(configParamsBytes, &outConfigParams)
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
	host := flag.String("host", cmd.DEFAULT_ACRA_CONFIGUI_HOST, "Host for configUI HTTP endpoint")
	port := flag.Int("port", cmd.DEFAULT_ACRA_CONFIGUI_PORT, "Port for configUI HTTP endpoint")
	acraHost = flag.String("acra_host", "localhost", "Host for Acraserver HTTP endpoint or proxy")
	acraPort = flag.Int("acra_port", cmd.DEFAULT_PROXY_API_PORT, "Port for Acraserver HTTP endpoint or proxy")
	staticPath = flag.String("static_path", cmd.DEFAULT_ACRA_CONFIGUI_STATIC, "Path to static content")
	debug = flag.Bool("d", false, "Turn on debug logging")
	flag.Parse()

	if *debug {
		logging.SetLogLevel(logging.LOG_DEBUG)
	} else {
		logging.SetLogLevel(logging.LOG_VERBOSE)
	}
	parseTemplate()
	configParamsBytes = parseConfig()
	http.HandleFunc("/index.html", index)
	http.HandleFunc("/", index)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(*staticPath))))
	http.HandleFunc("/acraserver/submit_setting", SubmitSettings)
	log.Info(fmt.Sprintf("AcraConfigUI is listening @ %s:%d with PID %d", *host, *port, os.Getpid()))
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", *host, *port), nil)
	check(err)
}
