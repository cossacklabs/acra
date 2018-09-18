/*
Copyright 2016, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package connector_mode stores different ways of AcraConnector modes: AcraConnector <-> AcraServer or
// AcraConnector <-> AcraTranslator
//
// https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter
package connector_mode

import "strings"

// ConnectorMode represents the destination point for AcraConnector: either AcraServer or AcraTranslator.
type ConnectorMode string

// Possible modes, default is AcraServerMode.
const (
	UndefinedMode      ConnectorMode = "UndefinedMode"
	AcraServerMode     ConnectorMode = "AcraServer"
	AcraTranslatorMode ConnectorMode = "AcraTranslator"
)

// ModeToServiceName return service name related with mode
func ModeToServiceName(mode ConnectorMode) string {
	switch mode {
	case AcraServerMode:
		return "AcraServer"
	case AcraTranslatorMode:
		return "AcraTranslator"
	default:
		return "Undefined service"
	}
}

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
