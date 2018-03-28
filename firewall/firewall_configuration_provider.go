package firewall

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"gopkg.in/yaml.v2"
	"github.com/cossacklabs/acra/firewall/handlers"
)

const BlacklistConfigStr = "blacklist"
const WhitelistConfigStr = "whitelist"

var ErrQuerySyntaxError = errors.New("fail to parse specified query")
var ErrStructureSyntaxError = errors.New("fail to parse specified structure")

type FirewallConfig struct {
	Handlers []struct {
		Handler string
		Queries []string
		Tables  []string
		Rules   []string
	}
}

func (firewall *Firewall) SetFirewallConfiguration(configuration []byte) error {

	err := updateFirewall(firewall, configuration)
	if err != nil {
		return err
	}

	return nil
}

func updateFirewall(firewall *Firewall, configuration []byte) error {

	var firewallConfiguration FirewallConfig

	err := yaml.Unmarshal(configuration, &firewallConfiguration)
	if err != nil {
		return err
	}

	//fmt.Println(firewallConfiguration)

	var firewallCheckers []QueryHandlerInterface
	for _, handlerConfiguration := range firewallConfiguration.Handlers {
		switch handlerConfiguration.Handler{
		case WhitelistConfigStr:
			whitelistHandler := &handlers.WhitelistHandler{}

			whitelistHandler.AddQueries(handlerConfiguration.Queries)
			whitelistHandler.AddTables(handlerConfiguration.Tables)
			whitelistHandler.AddRules(handlerConfiguration.Rules)

			firewallCheckers = append(firewallCheckers, whitelistHandler)
			break;
		case BlacklistConfigStr:
			blacklistHandler := &handlers.BlacklistHandler{}

			blacklistHandler.AddQueries(handlerConfiguration.Queries)
			blacklistHandler.AddTables(handlerConfiguration.Tables)
			blacklistHandler.AddRules(handlerConfiguration.Rules)

			firewallCheckers = append(firewallCheckers, blacklistHandler)
			break;
		default:
			break;
		}
	}

	err = testConfigurationSyntax(firewallCheckers)
	if err != nil {
		return err
	}

	for _, firewallChecker := range firewallCheckers{
		firewall.AddHandler(firewallChecker)
	}

	return nil
}

func testConfigurationSyntax(firewallCheckers []QueryHandlerInterface) error {

	for _, singleChecker := range firewallCheckers{
		//test syntax of queries
		activeQueries := singleChecker.GetActiveQueries()
		for _, activeQuery := range activeQueries {
			_, err := sqlparser.Parse(activeQuery)
			if err != nil {
				return ErrQuerySyntaxError
			}
		}
		//test syntax of structures
		activeStructures := singleChecker.GetActiveRules()
		for _, activeStructure := range activeStructures {
			_, err := sqlparser.Parse(activeStructure)
			if err != nil {
				return ErrStructureSyntaxError
			}
		}
	}

	return nil
}