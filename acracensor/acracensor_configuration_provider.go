package acracensor

import (
	"github.com/cossacklabs/acra/acracensor/handlers"
	"gopkg.in/yaml.v2"
)

const BlacklistConfigStr = "blacklist"
const WhitelistConfigStr = "whitelist"

type AcracensorConfig struct {
	Handlers []struct {
		Handler string
		Queries []string
		Tables  []string
		Rules   []string
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

	var firewallConfiguration AcracensorConfig

	err := yaml.Unmarshal(configuration, &firewallConfiguration)
	if err != nil {
		return err
	}

	for _, handlerConfiguration := range firewallConfiguration.Handlers {
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
		default:
			break
		}
	}

	return nil
}
