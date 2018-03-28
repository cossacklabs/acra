package firewall

import (
	"errors"
	"strings"
	"github.com/cossacklabs/acra/firewall/handlers"
	"github.com/xwb1989/sqlparser"
)

const blacklistStr = "blacklist"
const whitelistStr = "whitelist"

const handlerConfigHeader = 1
const queryConfigHeader = 2
const tableConfigHeader = 3
const structureConfigHeader = 4

var ErrQuerySyntaxError = errors.New("fail to parse specified query")
var ErrStructureSyntaxError = errors.New("fail to parse specified structure")


func (firewall *Firewall) SetFirewallConfiguration(configuration string) error {

	err := updateFirewall(firewall, configuration)
	if err != nil {
		return err
	}

	return nil
}

func updateFirewall(firewall *Firewall, configuration string) error {

	configLines := strings.Split(configuration, "\n")

	configLineType := 0
	handlerIndex := 0

	var firewallCheckers []QueryHandlerInterface

	for _, configLine := range configLines {
		switch configLine {
		case "[handler]":
			configLineType = handlerConfigHeader
			handlerIndex++
			break;
		case "[queries]":
			configLineType = queryConfigHeader
			break;
		case "[tables]":
			configLineType = tableConfigHeader
			break;
		case "[structures]":
			configLineType = structureConfigHeader
			break;
		case "\n":
			break;

		default:
			//skip empty strings in config
			if strings.EqualFold(configLine, ""){
				break;
			}
			switch configLineType {
			case handlerConfigHeader:
				if strings.EqualFold(configLine, whitelistStr){
					firewallCheckers = append(firewallCheckers, &handlers.WhitelistHandler{})
				}
				if strings.EqualFold(configLine, blacklistStr){
					firewallCheckers = append(firewallCheckers, &handlers.BlacklistHandler{})
				}

				break;
			case queryConfigHeader:
				firewallCheckers[handlerIndex - 1].AddQueries([]string{configLine})
				break;
			case tableConfigHeader:
				firewallCheckers[handlerIndex - 1].AddTables([]string{configLine})
				break;
			case structureConfigHeader:
				firewallCheckers[handlerIndex - 1].AddRules([]string{configLine})
				break;
			default:
				break;
			}

		}
	}

	err := testConfigurationSyntax(firewallCheckers)
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



