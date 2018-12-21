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

package acracensor

import (
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/acra-censor/handlers"
	log "github.com/sirupsen/logrus"
	"os"
)

// ServiceName to use in logs
const ServiceName = "acra-censor"

// AcraCensor describes censor data: query handler, logger and reaction on parsing errors.
type AcraCensor struct {
	handlers           []QueryHandlerInterface
	ignoreParseError   bool
	parseErrorsLogPath string
	logger             *log.Entry
}

// NewAcraCensor creates new censor object.
func NewAcraCensor() *AcraCensor {
	acraCensor := &AcraCensor{}
	acraCensor.logger = log.WithField("service", ServiceName)
	acraCensor.ignoreParseError = false
	acraCensor.parseErrorsLogPath = ""
	return acraCensor
}

// AddHandler adds handler to the list of Censor handlers.
func (acraCensor *AcraCensor) AddHandler(handler QueryHandlerInterface) {
	acraCensor.handlers = append(acraCensor.handlers, handler)
}

// RemoveHandler removes handler from the list of Censor handlers.
func (acraCensor *AcraCensor) RemoveHandler(handler QueryHandlerInterface) {
	for index, handlerFromRange := range acraCensor.handlers {
		if handlerFromRange == handler {
			acraCensor.handlers = append(acraCensor.handlers[:index], acraCensor.handlers[index+1:]...)
		}
	}
}

// ReleaseAll stops all handlers.
func (acraCensor *AcraCensor) ReleaseAll() {
	acraCensor.logger = log.WithField("service", "acra-censor")
	acraCensor.ignoreParseError = false
	for _, handler := range acraCensor.handlers {
		handler.Release()
	}
}

// HandleQuery processes every query through each handler.
func (acraCensor *AcraCensor) HandleQuery(rawQuery string) error {
	if len(acraCensor.handlers) == 0 {
		// no handlers, AcraCensor won't work
		return nil
	}
	normalizedQuery, queryWithHiddenValues, parsedQuery, err := common.HandleRawSQLQuery(rawQuery)
	if err == common.ErrQuerySyntaxError {
		acraCensor.logger.WithError(err).Warning("Failed to parse input query")
		if acraCensor.parseErrorsLogPath != "" {
			err := acraCensor.saveQuery(rawQuery)
			if err != nil {
				acraCensor.logger.WithError(err).Errorf("An error occurred while saving unparsable query")
				return err
			}
		}
		if acraCensor.ignoreParseError {
			acraCensor.logger.Infof("Unparsed query has been allowed")
			return nil
		}
		acraCensor.logger.Errorf("Unparsed query has been forbidden")
		return err
	}

	for _, handler := range acraCensor.handlers {
		// in QueryCapture Handler we use only redacted queries
		if queryCaptureHandler, ok := handler.(*handlers.QueryCaptureHandler); ok {
			queryCaptureHandler.CheckQuery(queryWithHiddenValues, parsedQuery)
			continue
		}
		// in QueryIgnore Handler we use only raw queries
		if queryIgnoreHandler, ok := handler.(*handlers.QueryIgnoreHandler); ok {
			continueHandling, _ := queryIgnoreHandler.CheckQuery(rawQuery, parsedQuery)
			if continueHandling {
				continue
			} else {
				break
			}
		}
		// remained handlers operate
		continueHandling, err := handler.CheckQuery(normalizedQuery, parsedQuery)
		if err != nil {
			acraCensor.logger.Errorf("Forbidden query: '%s'", queryWithHiddenValues)
			return err
		}
		//we don't have errors so allow query
		if !continueHandling {
			acraCensor.logger.Infof("Allowed query: '%s'", queryWithHiddenValues)
			return nil
		}
	}
	acraCensor.logger.Infof("Allowed query: '%s'", queryWithHiddenValues)
	return nil
}

func (acraCensor *AcraCensor) saveQuery(rawQuery string) error {
	openedFile, err := os.OpenFile(acraCensor.parseErrorsLogPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer openedFile.Close()

	_, err = openedFile.WriteString(rawQuery + "\n")
	if err != nil {
		return err
	}

	return nil
}
