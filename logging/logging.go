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

// Package logging contains custom log formatters (plaintext, JSON and CEF) to use through Acra components.
// Logging mode and verbosity level can be configured for AcraServer, AcraConnector, and AcraWebConfig in the
// corresponding yaml files or passed as CLI parameter.
//
// https://github.com/cossacklabs/acra/wiki/Logging
package logging

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

// Log modes
const (
	LogDebug = iota
	LogVerbose
	LogDiscard
)

const loggerKey = "logger"

// SetLogLevel sets logging level
func SetLogLevel(level int) {
	if level == LogDebug {
		log.SetLevel(log.DebugLevel)
	} else if level == LogVerbose {
		log.SetLevel(log.InfoLevel)
	} else if level == LogDiscard {
		log.SetLevel(log.WarnLevel)
	} else {
		panic(fmt.Sprintf("Incorrect log level - %v", level))
	}
}

// GetLogLevel gets logrus log level and returns int Acra log level
func GetLogLevel() int {
	if log.GetLevel() == log.DebugLevel {
		return LogDebug
	}
	if log.GetLevel() == log.InfoLevel {
		return LogVerbose
	}
	return LogDiscard
}

// CustomizeLogging changes logging format
func CustomizeLogging(loggingFormat string, serviceName string) {
	log.SetOutput(os.Stderr)
	log.SetFormatter(logFormatterFor(loggingFormat, serviceName))

	log.Debugf("Changed logging format to %s", loggingFormat)
}

func logFormatterFor(loggingFormat string, serviceName string) log.Formatter {
	loggingFormat = strings.ToLower(loggingFormat)

	if loggingFormat == "json" {
		return JSONFormatter(log.Fields{FieldKeyProduct: serviceName})

	} else if loggingFormat == "cef" {
		return CEFFormatter(log.Fields{FieldKeyProduct: serviceName})
	}

	return TextFormatter()
}

// SetLoggerToContext sets logger to corresponded context
func SetLoggerToContext(ctx context.Context, logger *log.Entry) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// GetLoggerFromContext gets logger from context, returns nil if no logger.
func GetLoggerFromContext(ctx context.Context) *log.Entry {
	if entry, ok := GetLoggerFromContextOk(ctx); ok {
		return entry
	}
	return nil
}

// GetLoggerFromContextOk gets logger from context, returns logger and success code.
func GetLoggerFromContextOk(ctx context.Context) (*log.Entry, bool) {
	entry, ok := ctx.Value(loggerKey).(*log.Entry)
	return entry, ok
}
