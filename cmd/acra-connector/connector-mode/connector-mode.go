package connector_mode

import "strings"

type ConnectorMode string

const (
	UndefinedMode ConnectorMode = "UndefinedMode"
	AcraServerMode ConnectorMode = "AcraServerMode"
	AcraTranslatorMode ConnectorMode = "AcraTranslatorMode"
)

func CheckConnectorMode(mode string) ConnectorMode {
	lowerCaseMode := strings.ToLower(mode)

	switch lowerCaseMode {
	case "acraserver":
		return AcraServerMode
	case "acratranslator":
		return AcraTranslatorMode
	}
	return UndefinedMode
}

