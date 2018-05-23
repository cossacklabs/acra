package acracensor

import (
	"github.com/cossacklabs/acra/acra-censor/handlers"
	"gopkg.in/yaml.v2"
	"strings"
)

const BlacklistConfigStr = "blacklist"
const WhitelistConfigStr = "whitelist"
const LoggerConfigStr = "logger"

type AcraCensorConfig struct {
	Handlers []struct {
		Handler  string
		Queries  []string
		Tables   []string
		Rules    []string
		Filepath string
	}
}

func (acraCensor *AcraCensor) LoadConfiguration(configuration []byte) ([]QueryHandlerInterface, error) {
	var handlers_ []QueryHandlerInterface

	var censorConfiguration AcraCensorConfig
	err := yaml.Unmarshal(configuration, &censorConfiguration)
	if err != nil {
		return nil, err
	}
	for _, handlerConfiguration := range censorConfiguration.Handlers {
		switch handlerConfiguration.Handler {
		case WhitelistConfigStr:
			whitelistHandler := &handlers.WhitelistHandler{}
			err := whitelistHandler.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return nil, err
			}
			whitelistHandler.AddTables(handlerConfiguration.Tables)
			err = whitelistHandler.AddRules(handlerConfiguration.Rules)
			if err != nil {
				return nil, err
			}
			acraCensor.AddHandler(whitelistHandler)
			handlers_ = append(handlers_, whitelistHandler)
			break
		case BlacklistConfigStr:
			blacklistHandler := &handlers.BlacklistHandler{}
			err := blacklistHandler.AddQueries(handlerConfiguration.Queries)
			if err != nil {
				return nil, err
			}
			blacklistHandler.AddTables(handlerConfiguration.Tables)
			err = blacklistHandler.AddRules(handlerConfiguration.Rules)
			if err != nil {
				return nil, err
			}
			acraCensor.AddHandler(blacklistHandler)
			handlers_ = append(handlers_, blacklistHandler)
			break
		case LoggerConfigStr:
			if strings.EqualFold(handlerConfiguration.Filepath, "") {
				break
			}
			logger, err := handlers.NewQueryCaptureHandler(handlerConfiguration.Filepath)
			if err != nil {
				return nil, err
			}
			acraCensor.AddHandler(logger)
			handlers_ = append(handlers_, logger)
			break
		default:
			break
		}
	}
	return handlers_, nil
}
