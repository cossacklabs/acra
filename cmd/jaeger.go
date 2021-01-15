/*
Copyright 2018, Cossack Labs Limited

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

package cmd

import (
	"errors"
	"flag"
	"contrib.go.opencensus.io/exporter/jaeger"
)

var options = jaeger.Options{
	AgentEndpoint:     "",
	CollectorEndpoint: "",
}

// ErrInvalidJaegerExporterEndpoint incorrect endpoint for jaeger
var ErrInvalidJaegerExporterEndpoint = errors.New("empty jaeger_agent_endpoint and jaeger_collector_endpoint")

// RegisterJaegerCmdParameters register cli parameters with flag for jaeger options
func RegisterJaegerCmdParameters() {
	flag.StringVar(&options.AgentEndpoint, "jaeger_agent_endpoint", options.AgentEndpoint, "Jaeger agent endpoint (for example, localhost:6831) that will be used to export trace data")
	flag.StringVar(&options.CollectorEndpoint, "jaeger_collector_endpoint", options.CollectorEndpoint, "Jaeger endpoint (for example, http://localhost:14268/api/traces) that will be used to export trace data")
	flag.StringVar(&options.Username, "jaeger_basic_auth_username", "", "Username used for basic auth (optional) to jaeger")
	flag.StringVar(&options.Password, "jaeger_basic_auth_password", "", "Password used for basic auth (optional) to jaeger")
}

// GetJaegerCmdParameters return jaeger.Options parsed from config/cmd parameters
func GetJaegerCmdParameters() jaeger.Options {
	return options
}

// ValidateJaegerCmdParameters validate cli parameters
func ValidateJaegerCmdParameters() error {
	if options.AgentEndpoint == "" && options.CollectorEndpoint == "" {
		return ErrInvalidJaegerExporterEndpoint
	}
	return nil
}
