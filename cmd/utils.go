package cmd

import (
	flag_ "flag"
	"fmt"
	"github.com/cossacklabs/acra/utils"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
)

var (
	config     = flag_.String("config", "", "path to config")
	dumpconfig = flag_.Bool("dumpconfig", false, "dump config")
)

func init() {
	// override default usage message by ours
	flag_.CommandLine.Usage = PrintDefaults
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
		name, usage := flag_.UnquoteUsage(flag)
		if len(name) > 0 {
			s += " " + name
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
		s += usage
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
		_, usage := flag_.UnquoteUsage(flag)
		s := fmt.Sprintf("# %v\n%v: %v\n", usage, flag.Name, flag.DefValue)
		fmt.Fprint(output, s, "\n")
	})
}

func Parse(config_path string) error {
	/*load from yaml config and cli. if dumpconfig option pass than generate config and exit*/

	// first parse using bultin flag
	err := flag_.CommandLine.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	if *config != "" {
		config_path = *config
	}
	var args []string
	// parse yaml and add params that wasn't passed from cli
	if config_path != "" {
		config_path, err := utils.AbsPath(config_path)
		if err != nil {
			return err
		}
		exists, err := utils.FileExists(config_path)
		if err != nil {
			return err
		}
		if exists {
			data, err := ioutil.ReadFile(config_path)
			if err != nil {
				return err
			}
			yaml_config := map[string]interface{}{}
			err = yaml.Unmarshal([]byte(data), &yaml_config)
			if err != nil {
				return err
			}
			set_args := make(map[string]bool)
			flag_.Visit(func(flag *flag_.Flag) {
				set_args[flag.Name] = true
			})
			// generate args list for flag.Parse as it was from cli args
			args = make([]string, 0)
			flag_.VisitAll(func(flag *flag_.Flag) {
				// generate only args that wasn't set from cli
				if _, already_set := set_args[flag.Name]; !already_set {
					if value, yaml_ok := yaml_config[flag.Name]; yaml_ok {
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
		var abs_path string
		if *config == "" {
			abs_path, err = utils.AbsPath(config_path)
			if err != nil {
				return err
			}
		} else {
			abs_path, err = utils.AbsPath(*config)
			if err != nil {
				return err
			}
		}

		dir_path := filepath.Dir(abs_path)
		err = os.MkdirAll(dir_path, 0744)
		if err != nil {
			return err
		}

		file, err := os.Create(abs_path)
		if err != nil {
			return err
		}
		defer file.Close()

		GenerateYaml(file)
		os.Exit(0)
	}
	return nil
}
