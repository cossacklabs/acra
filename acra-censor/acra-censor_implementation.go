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
	"github.com/cossacklabs/acra/acra-censor/handlers"
	log "github.com/sirupsen/logrus"
)

// ServiceName to use in logs
const ServiceName = "acra-censor"

// AcraCensor describes censor data: query handler, logger and reaction on parsing errors.
type AcraCensor struct {
	handlers         []QueryHandlerInterface
	ignoreParseError bool
	logger           *log.Entry
}

// NewAcraCensor creates new censor object.
func NewAcraCensor() *AcraCensor {
	acraCensor := &AcraCensor{}
	acraCensor.logger = log.WithField("service", ServiceName)
	acraCensor.ignoreParseError = false
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
func (acraCensor *AcraCensor) HandleQuery(query string) error {
	if query == "" {
		return nil
	}
	if len(acraCensor.handlers) == 0 {
		// no handlers, AcraCensor won't work
		return nil
	}
	normalizedQuery, queryWithHiddenValues, err := handlers.NormalizeAndRedactSQLQuery(query)
	if err == handlers.ErrQuerySyntaxError && acraCensor.ignoreParseError {
		acraCensor.logger.WithError(err).Infof("Parsing error on query (first %v symbols): %s", handlers.LogQueryLength, handlers.TrimStringToN(queryWithHiddenValues, handlers.LogQueryLength))

	}
	if err != nil {
		// ignore parsing errors to forward it as is to acra-censor to allow filter it via QueryIgnore handler
		normalizedQuery = query
	}
	for _, handler := range acraCensor.handlers {
		// in QueryCapture Handler use only redacted queries
		if queryCaptureHandler, ok := handler.(*handlers.QueryCaptureHandler); ok {
			queryCaptureHandler.CheckQuery(queryWithHiddenValues)
			continue
		}
		continueHandling, err := handler.CheckQuery(normalizedQuery)
		if err != nil {
			// continue to next handler
			if err == handlers.ErrQuerySyntaxError && acraCensor.ignoreParseError {
				continue
			}
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
