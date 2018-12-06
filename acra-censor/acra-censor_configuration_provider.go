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
	"github.com/cossacklabs/acra/acra-censor/handlers"
	"gopkg.in/yaml.v2"
	"strings"
)

// Query handlers' names.
const (
	BlacklistConfigStr    = "blacklist"
	WhitelistConfigStr    = "whitelist"
	QueryCaptureConfigStr = "query_capture"
	QueryIgnoreConfigStr  = "query_ignore"
)

// Config shows handlers configuration: queries, tables, patterns
type Config struct {
	Handlers []struct {
		Handler  string
		Queries  []string
		Tables   []string
		Patterns []string
		Filepath string
	}
	IgnoreParseError bool `yaml:"ignore_parse_error"`
}

// LoadConfiguration loads configuration of AcraCensor
func (acraCensor *AcraCensor) LoadConfiguration(configuration []byte) error {
	var censorConfiguration Config
	err := yaml.Unmarshal(configuration, &censorConfiguration)
	if err != nil {
		return err
	}
	acraCensor.ignoreParseError = censorConfiguration.IgnoreParseError
	for _, handlerConfiguration := range censorConfiguration.Handlers {
		switch handlerConfiguration.Handler {
		case WhitelistConfigStr:
			whitelistHandler := handlers.NewWhitelistHandler()
			err = whitelistHandler.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return err
			}
			whitelistHandler.AddTables(handlerConfiguration.Tables)
			err = whitelistHandler.AddPatterns(handlerConfiguration.Patterns)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(whitelistHandler)
			break
		case BlacklistConfigStr:
			blacklistHandler := handlers.NewBlacklistHandler()
			err = blacklistHandler.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return err
			}
			blacklistHandler.AddTables(handlerConfiguration.Tables)
			err = blacklistHandler.AddPatterns(handlerConfiguration.Patterns)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(blacklistHandler)
			break
		case QueryCaptureConfigStr:
			if strings.EqualFold(handlerConfiguration.Filepath, "") {
				break
			}
			queryCaptureHandler, err := handlers.NewQueryCaptureHandler(handlerConfiguration.Filepath)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(queryCaptureHandler)
			break
		case QueryIgnoreConfigStr:
			queryIgnoreHandler := handlers.NewQueryIgnoreHandler()
			queryIgnoreHandler.AddQueries(handlerConfiguration.Queries)
			acraCensor.AddHandler(queryIgnoreHandler)
			break
		default:
			break
		}
	}
	return nil
}
