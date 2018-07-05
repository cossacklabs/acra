package acracensor

import (
	"github.com/cossacklabs/acra/acra-censor/handlers"
	"gopkg.in/yaml.v2"
	"strings"
)

const BlacklistConfigStr = "blacklist"
const WhitelistConfigStr = "whitelist"
const QueryCaptureConfigStr = "query_capture"
const QueryIgnoreConfigStr = "query_ignore"

type AcraCensorConfig struct {
	Handlers []struct {
		Handler  string
		Queries  []string
		Tables   []string
		Rules    []string
		Filepath string
	}
	IgnoreParseError bool `yaml:"ignore_parse_error"`
}

func (acraCensor *AcraCensor) LoadConfiguration(configuration []byte) error {
	var censorConfiguration AcraCensorConfig
	err := yaml.Unmarshal(configuration, &censorConfiguration)
	if err != nil {
		return err
	}
	acraCensor.ignoreParseError = censorConfiguration.IgnoreParseError
	for _, handlerConfiguration := range censorConfiguration.Handlers {
		switch handlerConfiguration.Handler {
		case WhitelistConfigStr:
			whitelistHandler := &handlers.WhitelistHandler{}
			err := whitelistHandler.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return err
			}
			whitelistHandler.AddTables(handlerConfiguration.Tables)
			err = whitelistHandler.AddRules(handlerConfiguration.Rules)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(whitelistHandler)
			break
		case BlacklistConfigStr:
			blacklistHandler := &handlers.BlacklistHandler{}
			err := blacklistHandler.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return err
			}
			blacklistHandler.AddTables(handlerConfiguration.Tables)
			err = blacklistHandler.AddRules(handlerConfiguration.Rules)
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
