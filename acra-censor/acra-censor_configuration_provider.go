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
		Handler string
		Queries []string
		Tables  []string
		Rules   []string
		Filepath string
	}
}

func (acraCensor *AcraCensor) LoadConfiguration(configuration []byte) error {
	err := acraCensor.update(configuration)
	if err != nil {
		return err
	}
	return nil
}

func (acraCensor *AcraCensor) update(configuration []byte) error {
	var censorConfiguration AcraCensorConfig
	err := yaml.Unmarshal(configuration, &censorConfiguration)
	if err != nil {
		return err
	}
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
		case LoggerConfigStr:
			if strings.EqualFold(handlerConfiguration.Filepath, ""){
				break
			}
			logger, err := handlers.NewLoggingHandler(handlerConfiguration.Filepath)
			if err != nil {
				return err
			}
			acraCensor.AddHandler(logger)
			break
		default:
			break
		}
	}
	return nil
}
