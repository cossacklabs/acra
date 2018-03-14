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
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
	"os"
)


const (
	LOG_DEBUG = iota
	LOG_VERBOSE
	LOG_DISCARD
)

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

func CustomizeLogger(loggingFormat string, serviceName string) {
	log.SetOutput(os.Stderr)
	log.SetFormatter(LogFormatterFor(loggingFormat, serviceName))

	log.Infof("changed logging format to %s", loggingFormat)
}

func LogFormatterFor(loggingFormat string, serviceName string) log.Formatter {
	loggingFormat = strings.ToLower(loggingFormat)

	if loggingFormat == "json" {
		return CustomJSONFormatter(log.Fields{"product": serviceName})

	} else if loggingFormat == "cef" {
		return CustomCEFFormatter(log.Fields{"product": serviceName})
	}

	return CustomTextFormatter()
}
