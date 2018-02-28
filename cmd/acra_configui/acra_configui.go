package main

// TODO: errors output,

// sdfsdf

import (
	//"io/ioutil"
	//"html/template"
	"net/http"
	"log"
	"html/template"
	"path/filepath"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"time"
	"encoding/json"
	"strconv"
	"bytes"
	"os"
	"fmt"
	"flag"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type paramYAML struct {
	Name       string   `yaml:"name"`
	Title      string   `yaml:"title"`
	Value_type string   `yaml:"value_type"`
	Input_type string   `yaml:"input_type"`
	Values     []string `yaml:"values,flow"`
	Labels     []string `yaml:"labels,flow"`
}

type paramJSON struct {
	Name       string   `json:"name"`
	Title      string   `json:"title"`
	Value_type string   `json:"value_type"`
	Input_type string   `json:"input_type"`
	Values     []string `json:"values,flow"`
	Labels     []string `json:"labels,flow"`
}

type configParamsYAML struct {
	Config []paramYAML
}

type configParamsJSON struct {
	Config []paramJSON
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

type JsonResponse struct {
	Success bool `json:"success"`
}

func nop_map(map[string][]string) {}
func nop_string(string)           {}

func SubmitSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		panic(err)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequest("POST", "http://localhost:9292/setConfig", bytes.NewBuffer(jsonToServer))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonToServer)
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "require-sri-for script style")
	ip := filepath.Join("static", "index.html")
	tmpl, _ := template.ParseFiles(ip)
	var outConfigParams configParamsYAML
	configParamsYAML, err := ioutil.ReadFile("acraserver_config_vars.yaml")
	check(err)

	// get current config
	var netClient = &http.Client{
		Timeout: time.Second * 5,
	}
	serverResponse, err := netClient.Get("http://localhost:9292/getConfig")
	if err != nil {
		log.Printf("ERROR: api error - %s", err)
	}
	serverConfigDataJsonString, err := ioutil.ReadAll(serverResponse.Body)
	defer serverResponse.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	var serverConfigData ConfigAcraServer
	err = json.Unmarshal(serverConfigDataJsonString, &serverConfigData)
	if err != nil {
		log.Printf("ERROR: json.Unmarshal error - %s", err)
	}
	// log.Println(serverConfigData)
	// end get current config

	yaml.Unmarshal(configParamsYAML, &outConfigParams)

	var configParams configParamsJSON
	for _, item := range outConfigParams.Config {
		c := paramJSON{
			Name: item.Name,
			Title: item.Title,
			Value_type: item.Value_type,
			Input_type: item.Input_type,
			Values: item.Values,
			Labels: item.Labels,
		}
		configParams.Config = append(configParams.Config, c)
	}
	// log.Println(configParams)

	res, err := json.Marshal(configParams)

	tmpl.Execute(w, struct {
		ConfigParams string
		ConfigAcraServer
	}{
		string(res),
		serverConfigData,
	})
}

func main() {
	port := flag.Int("port", 8000, "Port for configUI HTTP endpoint")
	flag.Parse()
	http.HandleFunc("/index.html", index)
	http.HandleFunc("/", index)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.HandleFunc("/acraserver/submit_setting", SubmitSettings)
	log.Println(fmt.Sprintf("AcraConfigUI is listening @ :%d with PID %d", *port, os.Getpid()))
	err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	check(err)
}
