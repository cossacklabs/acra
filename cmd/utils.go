package cmd

import (
	"bytes"
	flag_ "flag"
	"fmt"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/utils"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
)

var (
	config     = flag_.String("config", "", "path to config")
	dumpconfig = flag_.Bool("dumpconfig", false, "dump config")
)

const (
	LOG_DEBUG = iota
	LOG_VERBOSE
	LOG_DISCARD
)

func init() {
	// override default usage message by ours
	flag_.CommandLine.Usage = PrintDefaults
}

func ValidateClientId(clientId string) {
	if !keystore.ValidateId([]byte(clientId)) {
		fmt.Println("Error: invalid client id, user only digits, letters and '_', '-', ' ' characters")
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

func PrintDefaults() {
	/* took from flag/flag.go and overrided arg display format (-/--) */
	flag_.CommandLine.VisitAll(func(flag *flag_.Flag) {
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

func GenerateYaml(output io.Writer) {
	flag_.CommandLine.VisitAll(func(flag *flag_.Flag) {
		s := fmt.Sprintf("# %v\n%v: %v\n", flag.Usage, flag.Name, flag.DefValue)
		fmt.Fprint(output, s, "\n")
	})
}

func Parse(configPath string) error {
	/*load from yaml config and cli. if dumpconfig option pass than generate config and exit*/

	// first parse using bultin flag
	err := flag_.CommandLine.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	if *config != "" {
		configPath = *config
	}
	var args []string
	// parse yaml and add params that wasn't passed from cli
	if configPath != "" {
		configPath, err := utils.AbsPath(configPath)
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
			yamlConfig := map[string]interface{}{}
			err = yaml.Unmarshal([]byte(data), &yamlConfig)
			if err != nil {
				return err
			}
			setArgs := make(map[string]bool)
			flag_.Visit(func(flag *flag_.Flag) {
				setArgs[flag.Name] = true
			})
			// generate args list for flag.Parse as it was from cli args
			args = make([]string, 0)
			flag_.VisitAll(func(flag *flag_.Flag) {
				// generate only args that wasn't set from cli
				if _, alreadySet := setArgs[flag.Name]; !alreadySet {
					if value, yamlOk := yamlConfig[flag.Name]; yamlOk {
						if value != nil {
							args = append(args, fmt.Sprintf("--%v=%v", flag.Name, value))
						}
					}
				}
			})
		}
	}
	// set options from config that wasn't set by cli
	err = flag_.CommandLine.Parse(args)
	if err != nil {
		return err
	}
	if *dumpconfig {
		var absPath string
		if *config == "" {
			absPath, err = utils.AbsPath(configPath)
			if err != nil {
				return err
			}
		} else {
			absPath, err = utils.AbsPath(*config)
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

		GenerateYaml(file)
		os.Exit(0)
	}
	return nil
}

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

func SetLogLevel(level int) {
	if level == LOG_DEBUG {
		log.SetOutput(os.Stdout)
	} else if level == LOG_VERBOSE {
		log.SetOutput(NewNotDebugWriter(os.Stdout))
	} else if level == LOG_DISCARD {
		log.SetOutput(ioutil.Discard)
	} else {
		panic(fmt.Sprintf("Incorrect log level - %v", level))
	}
}
