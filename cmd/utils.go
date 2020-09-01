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

// Package cmd contains shared settings/constants among most of Acra component utilities.
package cmd

import (
	"errors"
	flag_ "flag"
	"fmt"
	"github.com/cossacklabs/acra/logging"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"context"

	"encoding/base64"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

var (
	config                   = flag_.String("config_file", "", "path to config")
	dumpconfig               = flag_.Bool("dump_config", false, "dump config")
	generateMarkdownArgTable = flag_.Bool("generate_markdown_args_table", false, "Generate with yaml config markdown text file with descriptions of all args")
)

// Argument and configuration parsing errors.
var (
	ErrDumpRequested = errors.New("configurtion dump requested")
)

func init() {
	// override default usage message by ours
	flag_.CommandLine.Usage = func() {
		PrintFlags(flag_.CommandLine)
	}
}

// SignalCallback callback function
type SignalCallback func()

// SignalHandler sends Signal to listeners and call registered callbacks
type SignalHandler struct {
	ch        chan os.Signal
	listeners []net.Listener
	callbacks []SignalCallback
	signals   []os.Signal
}

// NewSignalHandler returns new SignalHandler registered for particular os.Signals
func NewSignalHandler(handledSignals []os.Signal) (*SignalHandler, error) {
	return &SignalHandler{ch: make(chan os.Signal), signals: handledSignals}, nil
}

// AddListener to listeners list
func (handler *SignalHandler) AddListener(listener net.Listener) {
	handler.listeners = append(handler.listeners, listener)
}

// GetChannel returns channel of os.Signal
func (handler *SignalHandler) GetChannel() chan os.Signal {
	return handler.ch
}

// AddCallback to callbacks list
func (handler *SignalHandler) AddCallback(callback SignalCallback) {
	handler.callbacks = append(handler.callbacks, callback)
}

// Register should be called as goroutine
func (handler *SignalHandler) Register() {
	signal.Notify(handler.ch, handler.signals...)

	<-handler.ch

	for _, listener := range handler.listeners {
		listener.Close()
	}
	for _, callback := range handler.callbacks {
		callback()
	}
	os.Exit(0)
}

// RegisterWithContext is a no-exit version of Register function with context usage
func (handler *SignalHandler) RegisterWithContext(globalContext context.Context) {
	signal.Notify(handler.ch, handler.signals...)
	for {
		select {
		case <-handler.ch:
			for _, listener := range handler.listeners {
				listener.Close()
			}
			for _, callback := range handler.callbacks {
				callback()
			}
		case <-globalContext.Done():
			// got signal for shutdown, so just return
			return
		}
	}
}

// ValidateClientID checks that clientID has digits, letters, _ - ' '
func ValidateClientID(clientID string) {
	if !keystore.ValidateID([]byte(clientID)) {
		log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorInvalidClientID).Errorf(
			"Invalid client ID,  %d <= len(client ID) <= %d, only digits, letters and '_', '-', ' ' characters",
			keystore.MinClientIDLength, keystore.MaxClientIDLength)
		os.Exit(1)
	}
}

func isZeroValue(flag *flag_.Flag, value string) bool {
	/* took from flag/flag.go */

	// Build a zero value of the flag's Value type, and see if the
	// result of calling its String method equals the value passed in.
	// This works unless the Value type is itself an interface type.
	typ := reflect.TypeOf(flag.Value)
	var z reflect.Value
	if typ.Kind() == reflect.Ptr {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.Zero(typ)
	}
	if value == z.Interface().(flag_.Value).String() {
		return true
	}

	switch value {
	case "false":
		return true
	case "":
		return true
	case "0":
		return true
	}
	return false
}

// PrintFlags pretty-prints CLI flag set with default values to stderr.
func PrintFlags(flags *flag_.FlagSet) {
	/* took from flag/flag.go and overrided arg display format (-/--) */
	flags.VisitAll(func(flag *flag_.Flag) {
		var s string
		if len(flag.Name) > 2 {
			s = fmt.Sprintf("  --%s", flag.Name) // Two spaces before -; see next two comments.
		} else {
			s = fmt.Sprintf("  -%s", flag.Name) // Two spaces before -; see next two comments.
		}
		// Boolean flags of one ASCII letter are so common we
		// treat them specially, putting their usage on the same line.
		if len(s) <= 4 {
			// space, space, '-', 'x'.
			s += "\t"
		} else {
			// Four spaces before the tab triggers good alignment
			// for both 4- and 8-space tab stops.
			s += "\n    \t"
		}
		s += flag.Usage
		if !isZeroValue(flag, flag.DefValue) {
			getter, ok := flag.Value.(flag_.Getter)
			if !ok {
				return
			}

			if _, ok := getter.Get().(string); ok {
				// put quotes on the value
				s += fmt.Sprintf(" (default %q)", flag.DefValue)
			} else {
				s += fmt.Sprintf(" (default %v)", flag.DefValue)
			}
		}
		fmt.Fprint(os.Stderr, s, "\n")
	})
}

func visitFlagSets(flagSets []*flag_.FlagSet, visit func(flag *flag_.Flag)) {
	seenNames := make(map[string]struct{})
	for _, flags := range flagSets {
		flags.VisitAll(func(flag *flag_.Flag) {
			if _, visited := seenNames[flag.Name]; !visited {
				visit(flag)
				seenNames[flag.Name] = struct{}{}
			}
		})
	}
}

// GenerateYaml generates YAML file from CLI params
func GenerateYaml(output io.Writer, useDefault bool) {
	GenerateYamlFromFlagSets([]*flag_.FlagSet{flag_.CommandLine}, output, useDefault)
}

// GenerateYamlFromFlagSets generates YAML file from CLI flag sets.
func GenerateYamlFromFlagSets(flagSets []*flag_.FlagSet, output io.Writer, useDefault bool) {
	// write version as first line in yaml format
	if _, err := fmt.Fprintf(output, "version: %s\n", utils.VERSION); err != nil {
		panic(err)
	}
	visitFlagSets(flagSets, func(flag *flag_.Flag) {
		var s string
		if useDefault {
			s = fmt.Sprintf("# %v\n%v: %v\n", flag.Usage, flag.Name, flag.DefValue)
		} else {
			s = fmt.Sprintf("# %v\n%v: %v\n", flag.Usage, flag.Name, flag.Value)
		}
		fmt.Fprint(output, s, "\n")
	})
}

// GenerateMarkdownDoc generates Markdown file from CLI params
func GenerateMarkdownDoc(output io.Writer, serviceName string) {
	GenerateMarkdownDocFromFlagSets([]*flag_.FlagSet{flag_.CommandLine}, output, serviceName)
}

// GenerateMarkdownDocFromFlagSets generates Markdown file from CLI flag sets.
func GenerateMarkdownDocFromFlagSets(flagSets []*flag_.FlagSet, output io.Writer, serviceName string) {
	// escape column separator symbol from text
	escapeColumn := func(text string) string {
		return strings.Replace(text, "|", "\\|", -1)
	}
	// table header with service name
	// |serviceName | arg name | rename to | default value | description|
	// |:-:         |:-:       |:-:        |:-:            |:-:         |
	fmt.Fprintf(output, "|%v|||||\n|:-:|:-:|:-:|:-:|:-:|\n", serviceName)
	visitFlagSets(flagSets, func(flag *flag_.Flag) {
		fmt.Fprintf(output, "||%v||%v|%v|\n", flag.Name, flag.DefValue, escapeColumn(flag.Usage))
	})
}

// DumpConfig writes CLI params to configPath
func DumpConfig(configPath, serviceName string, useDefault bool) error {
	return DumpConfigFromFlagSets([]*flag_.FlagSet{flag_.CommandLine}, configPath, serviceName, useDefault)
}

// DumpConfigFromFlagSets writes CLI params to configPath
func DumpConfigFromFlagSets(flagSets []*flag_.FlagSet, configPath, serviceName string, useDefault bool) error {
	var absPath string
	var err error

	if *config == "" {
		absPath, err = filepath.Abs(configPath)
		if err != nil {
			return err
		}
	} else {
		absPath, err = filepath.Abs(*config)
		if err != nil {
			return err
		}
	}

	dirPath := filepath.Dir(absPath)
	err = os.MkdirAll(dirPath, 0744)
	if err != nil {
		return err
	}

	file, err := os.Create(absPath)
	if err != nil {
		return err
	}
	defer file.Close()

	GenerateYamlFromFlagSets(flagSets, file, useDefault)

	if *generateMarkdownArgTable {
		file2, err := os.Create(fmt.Sprintf("%v/markdown_%v.md", dirPath, serviceName))
		if err != nil {
			return err
		}

		GenerateMarkdownDocFromFlagSets(flagSets, file2, serviceName)
	}
	log.Infof("Config dumped to %s", configPath)
	return nil
}

func checkVersion(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	configVersion, ok := config["version"]
	if !ok {
		return errors.New("config hasn't version key")
	}
	versionValue, ok := configVersion.(string)
	if !ok {
		return errors.New("value of version is not string")
	}

	version, err := utils.ParseVersion(versionValue)
	if err != nil {
		return err
	}

	serverVersion, err := utils.GetParsedVersion()
	if err != nil {
		return err
	}

	if serverVersion.CompareOnly(utils.MajorFlag|utils.MinorFlag, version) != utils.Equal {
		return fmt.Errorf("config version \"%s\" is not supported, expects \"%s\" version", version.String(), serverVersion.String())
	}
	return nil
}

// Parse parses flag settings from YAML config file and command line.
func Parse(configPath, serviceName string) error {
	err := ParseFlagsWithConfig(flag_.CommandLine, os.Args[1:], configPath, serviceName)
	if err == ErrDumpRequested {
		DumpConfig(configPath, serviceName, true)
		os.Exit(0)
	}
	return err
}

// ParseFlagsWithConfig parses flag settings from YAML config file and command line.
func ParseFlagsWithConfig(flags *flag_.FlagSet, arguments []string, configPath, serviceName string) error {
	/*load from yaml config and cli. if dumpconfig option pass than generate config and exit*/
	log.Debugf("Parsing config from path %v", configPath)
	// first parse using bultin flag
	err := flags.Parse(arguments)
	if err != nil {
		return err
	}

	if *config != "" {
		configPath = *config
	}
	var yamlConfig map[string]interface{}
	var extraArgs []string
	// parse yaml and add params that wasn't passed from cli
	if configPath != "" {

		configPath, err := filepath.Abs(configPath)
		if err != nil {
			return err
		}
		exists, err := utils.FileExists(configPath)
		if err != nil {
			return err
		}
		if exists {
			data, err := ioutil.ReadFile(configPath)
			if err != nil {
				return err
			}
			err = yaml.Unmarshal([]byte(data), &yamlConfig)
			if err != nil {
				return err
			}
			setArgs := make(map[string]bool)
			flags.Visit(func(flag *flag_.Flag) {
				setArgs[flag.Name] = true
			})
			// generate args list for flag.Parse as it was from cli args
			flags.VisitAll(func(flag *flag_.Flag) {
				// generate only args that wasn't set from cli
				if _, alreadySet := setArgs[flag.Name]; !alreadySet {
					if value, yamlOk := yamlConfig[flag.Name]; yamlOk {
						if value != nil {
							extraArgs = append(extraArgs, fmt.Sprintf("--%v=%v", flag.Name, value))
						}
					}
				}
			})
		}
	}
	// Set global options from config that wasn't set by CLI, if there are any.
	if len(extraArgs) != 0 {
		err = flags.Parse(extraArgs)
		if err != nil {
			return err
		}
		// Parse the command-line options again so that flag.Args() returns
		// whatever was left on the actual command-line, not the config values.
		flags.Parse(arguments)
	}
	if *dumpconfig {
		return ErrDumpRequested
	}
	if err = checkVersion(yamlConfig); err != nil {
		return err
	}
	return nil
}

// Argon2Params describes params for Argon2 hashing
type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Length  uint32
}

// UserAuth describes user params for password hashing: salt, params, hash
type UserAuth struct {
	Salt string
	Argon2Params
	Hash []byte
}

// UserAuthString returns string representation of UserAuth
func (auth UserAuth) UserAuthString(userDataDelimiter string, paramsDelimiter string) string {
	var userData []string
	var argon2P []string
	argon2P = append(argon2P, strconv.FormatUint(uint64(auth.Argon2Params.Time), 10))
	argon2P = append(argon2P, strconv.FormatUint(uint64(auth.Argon2Params.Memory), 10))
	argon2P = append(argon2P, strconv.FormatUint(uint64(auth.Argon2Params.Threads), 10))
	argon2P = append(argon2P, strconv.FormatUint(uint64(auth.Argon2Params.Length), 10))
	hash := base64.StdEncoding.EncodeToString(auth.Hash)
	userData = append(userData, auth.Salt)
	userData = append(userData, strings.Join(argon2P, paramsDelimiter))
	userData = append(userData, hash)
	return strings.Join(userData, userDataDelimiter)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var randSrc = rand.NewSource(time.Now().UnixNano())

// RandomStringBytes getting random string using faster randSrc.Int63() and true distribution for letterBytes.
func RandomStringBytes(n int) string {
	b := make([]byte, n)
	// A randSrc.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, randSrc.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSrc.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
