package firewall

import (
	"github.com/cossacklabs/acra/firewall/handlers"
	"gopkg.in/yaml.v2"
)

const BlacklistConfigStr = "blacklist"
const WhitelistConfigStr = "whitelist"

type FirewallConfig struct {
	Handlers []struct {
		Handler string
		Queries []string
		Tables  []string
		Rules   []string
	}
}

func (firewall *Firewall) LoadConfiguration(configuration []byte) error {

	err := firewall.update(configuration)
	if err != nil {
		return err
	}

	return nil
}

func (firewall *Firewall) update(configuration []byte) error {

	var firewallConfiguration FirewallConfig

	err := yaml.Unmarshal(configuration, &firewallConfiguration)
	if err != nil {
		return err
	}

	var firewallCheckers []QueryHandlerInterface

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

			firewallCheckers = append(firewallCheckers, whitelistHandler)
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

			firewallCheckers = append(firewallCheckers, blacklistHandler)
			break
		default:
			break
		}
	}

	for _, firewallChecker := range firewallCheckers {
		firewall.AddHandler(firewallChecker)
	}

	return nil
}
