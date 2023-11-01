package args

import (
	"flag"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// ServiceExtractor encapsulate logic of parsing parameters from CLI and config
type ServiceExtractor struct {
	configData map[string]interface{}
	flags      *flag.FlagSet
}

// NewServiceExtractor create new ServiceExtractor
func NewServiceExtractor(flags *flag.FlagSet, config map[string]interface{}) *ServiceExtractor {
	return &ServiceExtractor{
		configData: config,
		flags:      flags,
	}
}

// GetString parse string param from CLI and Config in the following order
// CLI param -> Config param -> CLI generalParam if present -> Config generalParam if present -> CLI default value
func (e *ServiceExtractor) GetString(param, generalParam string) string {
	if isFlagSet(param, e.flags) {
		if f := e.flags.Lookup(param); f != nil {
			if value := f.Value.String(); value != "" {
				return value
			}
		}
	}

	if rawValue, ok := e.configData[param]; ok {
		value, ok := rawValue.(string)
		if ok {
			return value
		}
	}

	if generalParam != "" {
		if isFlagSet(generalParam, e.flags) {
			if f := e.flags.Lookup(generalParam); f != nil {
				if value := f.Value.String(); value != "" {
					return value
				}
			}
		}

		if rawValue, ok := e.configData[generalParam]; ok {
			value, ok := rawValue.(string)
			if ok {
				return value
			}
		}
	}

	return getCLIDefault[string](param, e.flags)
}

// GetBool parse bool param from CLI and Config in the following order
// CLI param -> Config param -> CLI generalParam if present -> Config generalParam if present -> CLI default value
func (e *ServiceExtractor) GetBool(param, generalParam string) bool {
	if isFlagSet(param, e.flags) {
		if f := e.flags.Lookup(param); f != nil {
			v, err := strconv.ParseBool(f.Value.String())
			if err != nil {
				log.WithField("value", f.Value.String).Fatalf("Can't cast %s to boolean value", param)
			}
			return v
		}
	}

	if rawValue, ok := e.configData[param]; ok {
		value, ok := rawValue.(bool)
		if ok {
			return value
		}
	}

	if generalParam != "" {
		if isFlagSet(generalParam, e.flags) {
			if f := e.flags.Lookup(generalParam); f != nil {
				v, err := strconv.ParseBool(f.Value.String())
				if err != nil {
					log.WithField("value", f.Value.String).Fatalf("Can't cast %s to boolean value", param)
				}
				return v
			}
		}

		if rawValue, ok := e.configData[generalParam]; ok {
			value, ok := rawValue.(bool)
			if ok {
				return value
			}
		}
	}

	return getCLIDefault[bool](param, e.flags)
}

// GetInt parse int param from CLI and Config in the following order
// CLI param -> Config param -> CLI generalParam if present -> Config generalParam if present -> CLI default value
func (e *ServiceExtractor) GetInt(param, generalParam string) int {
	if isFlagSet(param, e.flags) {
		if f := e.flags.Lookup(param); f != nil {
			v, err := strconv.ParseInt(f.Value.String(), 10, 64)
			if err != nil {
				log.WithField("value", f.Value.String).Fatalf("Can't cast %s to integer value", param)
			}
			return int(v)
		}
	}

	if rawValue, ok := e.configData[param]; ok {
		value, ok := rawValue.(int)
		if ok {
			return value
		}
	}

	if generalParam != "" {
		if isFlagSet(generalParam, e.flags) {
			if f := e.flags.Lookup(generalParam); f != nil {
				v, err := strconv.ParseInt(f.Value.String(), 10, 64)
				if err != nil {
					log.WithField("value", f.Value.String).Fatalf("Can't cast %s to integer value", param)
				}
				return int(v)
			}
		}

		if rawValue, ok := e.configData[generalParam]; ok {
			value, ok := rawValue.(int)
			if ok {
				return value
			}
		}
	}

	return getCLIDefault[int](param, e.flags)
}

// IsFlagSet returns true if flag explicitly set via CLI arguments
// Don't move it to the cmd package due to import cycle
func isFlagSet(name string, flagset *flag.FlagSet) bool {
	set := false
	flagset.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func getCLIDefault[T any](name string, flagset *flag.FlagSet) T {
	var res interface{}
	flagset.VisitAll(func(f *flag.Flag) {
		if f.Name == name {
			v, err := strconv.ParseInt(f.Value.String(), 10, 64)
			if err == nil {
				res = int(v)
				return
			}

			boolVal, err := strconv.ParseBool(f.Value.String())
			if err == nil {
				res = boolVal
				return
			}

			res = f.Value.String()
		}
	})

	val, ok := res.(T)
	if !ok {
		var temp T
		return temp
	}
	return val
}
