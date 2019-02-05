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
	"flag"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/exporter/jaeger"
	"go.opencensus.io/trace"
	"os"
)

var traceToLog = false
var traceToJaeger = false

// RegisterTracingCmdParameters register cli parameters with flag for tracing
func RegisterTracingCmdParameters() {
	flag.BoolVar(&traceToLog, "tracing_log_enable", false, "Export trace data to log")
	flag.BoolVar(&traceToJaeger, "tracing_jaeger_enable", false, "Export trace data to jaeger")
}

// IsTraceToLogOn return true if turned on tracing to log output
func IsTraceToLogOn() bool {
	return traceToLog
}

// IsTraceToJaegerOn return true if turned on tracing to jaeger
func IsTraceToJaegerOn() bool {
	return traceToJaeger
}

// SetupTracing with global options related with exporters
func SetupTracing(serviceName string) {
	if IsTraceToLogOn() {
		trace.RegisterExporter(&logging.LogSpanExporter{})
	}
	if IsTraceToJaegerOn() {
		if err := ValidateJaegerCmdParameters(); err != nil {
			log.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorJaegerInvalidParameters).WithError(err).Errorln("Invalid jaeger parameters")
			os.Exit(1)
		}
		jaegerOptions := GetJaegerCmdParameters()
		jaegerOptions.ServiceName = serviceName
		jaegerEndpoint, err := jaeger.NewExporter(jaegerOptions)
		if err != nil {
			log.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorJaegerExporter).Fatalf("Failed to create the Jaeger exporter: %v", err)
			os.Exit(1)
		}
		// And now finally register it as a Trace Exporter
		trace.RegisterExporter(jaegerEndpoint)
	}
}
