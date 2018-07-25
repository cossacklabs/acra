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

// AcraCensorConfig shows handlers configuration: queries, tables, rules
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

// LoadConfiguration loads configuration of AcraCensor rules
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
			whitelistHandler := handlers.NewWhitelistHandler()
			whitelistHandler.AddQueries(handlerConfiguration.Queries)
			whitelistHandler.AddTables(handlerConfiguration.Tables)
			err = whitelistHandler.AddRules(handlerConfiguration.Rules)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(whitelistHandler)
			break
		case BlacklistConfigStr:
			blacklistHandler := handlers.NewBlacklistHandler()
			blacklistHandler.AddQueries(handlerConfiguration.Queries)
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
