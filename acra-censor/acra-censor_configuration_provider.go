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

package acracensor

import (
	"errors"
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/acra-censor/handlers"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"strings"
)

// MinimalCensorConfigVersion min version of config that support acra-censor
var MinimalCensorConfigVersion = "0.85.0"

// Query handlers' names.
const (
	DenyConfigStr         = "deny"
	AllowConfigStr        = "allow"
	DenyAllConfigStr      = "denyall"
	AllowAllConfigStr     = "allowall"
	QueryCaptureConfigStr = "query_capture"
	QueryIgnoreConfigStr  = "query_ignore"
)

// Config shows handlers configuration: queries, tables, patterns
type Config struct {
	Version          string `yaml:"version"`
	IgnoreParseError bool   `yaml:"ignore_parse_error"`
	ParseErrorsLog   string `yaml:"parse_errors_log"`
	Handlers         []struct {
		Handler  string
		Queries  []string
		Tables   []string
		Patterns []string
		FilePath string
	}
}

// ErrUnsupportedConfigVersion acra-censor's config has version less than MinimalCensorConfigVersion
var ErrUnsupportedConfigVersion = errors.New("acra-censor's config is outdated")

// LoadConfiguration loads configuration of AcraCensor
func (acraCensor *AcraCensor) LoadConfiguration(configuration []byte) error {
	var censorConfiguration Config
	err := yaml.Unmarshal(configuration, &censorConfiguration)
	if err != nil {
		return err
	}
	if len(censorConfiguration.Version) == 0 {
		return ErrUnsupportedConfigVersion
	}
	configVersion, err := utils.ParseVersion(censorConfiguration.Version)
	if err != nil {
		return err
	}
	currentlySupportedVersion, err := utils.ParseVersion(MinimalCensorConfigVersion)
	if err != nil {
		return err
	}
	if currentlySupportedVersion.Compare(configVersion) == utils.Greater {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSetupError).
			Errorln("AcraCensor config file version is not supported: probably AcraCensor configuration " +
				"(acra-censor.yaml) is outdated, check docs for deprecation warnings " +
				"https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall")
		// censor has version newer than config
		return ErrUnsupportedConfigVersion
	}
	acraCensor.ignoreParseError = censorConfiguration.IgnoreParseError
	if !strings.EqualFold(censorConfiguration.ParseErrorsLog, "") {
		queryWriter, err := common.NewFileQueryWriter(censorConfiguration.ParseErrorsLog)
		if err != nil {
			return err
		}
		go queryWriter.Start()
		acraCensor.unparsedQueriesWriter = queryWriter
	}

	for _, handlerConfiguration := range censorConfiguration.Handlers {
		switch handlerConfiguration.Handler {
		case AllowConfigStr:
			allow := handlers.NewAllowHandler(acraCensor.parser)
			err = allow.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return err
			}
			allow.AddTables(handlerConfiguration.Tables)
			err = allow.AddPatterns(handlerConfiguration.Patterns)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(allow)
		case DenyConfigStr:
			deny := handlers.NewDenyHandler(acraCensor.parser)
			err = deny.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return err
			}
			deny.AddTables(handlerConfiguration.Tables)
			err = deny.AddPatterns(handlerConfiguration.Patterns)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(deny)
		case AllowAllConfigStr:
			allowAll := handlers.NewAllowallHandler()
			acraCensor.AddHandler(allowAll)
		case DenyAllConfigStr:
			denyAll := handlers.NewDenyallHandler()
			acraCensor.AddHandler(denyAll)
		case QueryIgnoreConfigStr:
			queryIgnoreHandler := handlers.NewQueryIgnoreHandler(acraCensor.parser)
			queryIgnoreHandler.AddQueries(handlerConfiguration.Queries)
			acraCensor.AddHandler(queryIgnoreHandler)
		case QueryCaptureConfigStr:
			queryCaptureHandler, err := handlers.NewQueryCaptureHandler(handlerConfiguration.FilePath, acraCensor.parser)
			if err != nil {
				return err
			}
			go queryCaptureHandler.Start()
			acraCensor.AddHandler(queryCaptureHandler)
		default:
			acraCensor.logger.
				WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSetupError).
				Errorln("Unexpected handler in configuration: probably AcraCensor configuration (acra-censor.yaml) is outdated")
			return common.ErrCensorConfigurationError
		}
	}
	return nil
}
