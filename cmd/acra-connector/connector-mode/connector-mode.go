package connector_mode

import "strings"

// ConnectorMode connection mode of AcraConnector
type ConnectorMode string

// Possible modes, default is AcraServerMode.
const (
	UndefinedMode      ConnectorMode = "UndefinedMode"
	AcraServerMode     ConnectorMode = "AcraServer"
	AcraTranslatorMode ConnectorMode = "AcraTranslator"
)

// CheckConnectorMode converts string to ConnectorMode.
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
