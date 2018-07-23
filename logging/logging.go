// Copyright 2016, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package logging

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

const (
	LOG_DEBUG = iota
	LOG_VERBOSE
	LOG_DISCARD
)

const loggerKey = "logger"

func SetLogLevel(level int) {
	if level == LOG_DEBUG {
		log.SetLevel(log.DebugLevel)
	} else if level == LOG_VERBOSE {
		log.SetLevel(log.InfoLevel)
	} else if level == LOG_DISCARD {
		log.SetLevel(log.WarnLevel)
	} else {
		panic(fmt.Sprintf("Incorrect log level - %v", level))
	}
}

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

func SetLoggerToContext(ctx context.Context, logger *log.Entry) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func GetLoggerFromContext(ctx context.Context) *log.Entry {
	if entry, ok := GetLoggerFromContextOk(ctx); ok {
		return entry
	}
	return nil
}

func GetLoggerFromContextOk(ctx context.Context) (*log.Entry, bool) {
	entry, ok := ctx.Value(loggerKey).(*log.Entry)
	return entry, ok
}
