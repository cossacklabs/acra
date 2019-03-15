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
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
)

// ServiceName to use in logs
const ServiceName = "acra-censor"

// AcraCensor describes censor data: query handler, logger and reaction on parsing errors.
type AcraCensor struct {
	handlers              []QueryHandlerInterface
	ignoreParseError      bool
	unparsedQueriesWriter *common.QueryWriter
	logger                *log.Entry
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
	acraCensor.ignoreParseError = false
	for _, handler := range acraCensor.handlers {
		handler.Release()
	}
	if acraCensor.unparsedQueriesWriter != nil {
		acraCensor.unparsedQueriesWriter.Free()
	}

}

// HandleQuery processes every query through each handler.
func (acraCensor *AcraCensor) HandleQuery(rawQuery string) error {
	if len(acraCensor.handlers) == 0 && acraCensor.unparsedQueriesWriter == nil {
		// no handlers, AcraCensor won't work
		return nil
	}
	normalizedQuery, queryWithHiddenValues, parsedQuery, err := common.HandleRawSQLQuery(rawQuery)
	// Unparsed query handling
	if err == common.ErrQuerySyntaxError {
		acraCensor.saveUnparsedQuery(rawQuery)
		if acraCensor.ignoreParseError {
			// log warning if we ignore such errors
			acraCensor.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Warning("Failed to parse input query")
		} else {
			acraCensor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Errorln("Unparsed query has been denied")
			return err
		}
	}
	// Handlers work
	for _, handler := range acraCensor.handlers {
		if queryCaptureHandler, ok := handler.(*handlers.QueryCaptureHandler); ok {
			queryCaptureHandler.CheckQuery(queryWithHiddenValues, parsedQuery)
			continue
		}
		if queryIgnoreHandler, ok := handler.(*handlers.QueryIgnoreHandler); ok {
			continueHandling, _ := queryIgnoreHandler.CheckQuery(rawQuery, nil)
			if !continueHandling {
				acraCensor.logAllowedQuery(queryWithHiddenValues, parsedQuery)
				return nil
			}
			continue
		}
		// Security checks (allow/deny handlers)
		continueHandling, err := handler.CheckQuery(normalizedQuery, parsedQuery)
		if err != nil {
			acraCensor.logDeniedQuery(queryWithHiddenValues, handler, parsedQuery)
			return err
		}
		//we don't have errors so allow query
		if !continueHandling {
			acraCensor.logAllowedQuery(queryWithHiddenValues, parsedQuery)
			return nil
		}
	}
	acraCensor.logAllowedQuery(queryWithHiddenValues, parsedQuery)
	return nil
}

func (acraCensor *AcraCensor) logAllowedQuery(queryWithHiddenValues string, parsedQuery sqlparser.Statement) {
	if parsedQuery != nil && queryWithHiddenValues != "" {
		acraCensor.logger.Infof("Allowed query: '%s'", common.TrimStringToN(queryWithHiddenValues, common.LogQueryLength))
		return
	}
	if parsedQuery == nil && queryWithHiddenValues == "" {
		acraCensor.logger.Infoln("Allowed query can't be shown in plaintext")
		return
	}
	acraCensor.logger.Debugf("parsedQuery: %T, queryWithHiddenValues: %s", parsedQuery, queryWithHiddenValues)
	return
}

func (acraCensor *AcraCensor) logDeniedQuery(queryWithHiddenValues string, handler QueryHandlerInterface, parsedQuery sqlparser.Statement) {
	if parsedQuery != nil && queryWithHiddenValues != "" {
		acraCensor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).Errorf("Denied query: '%s'", common.TrimStringToN(queryWithHiddenValues, common.LogQueryLength))
		acraCensor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).Debugf("Denied query by %T", handler)
		return
	}
	if parsedQuery == nil && queryWithHiddenValues == "" {
		acraCensor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).Errorln("Denied query can't be shown in plaintext")
		acraCensor.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).Debugf("Denied query by %T", handler)
		return
	}
	acraCensor.logger.Debugf("parsedQuery: %T, queryWithHiddenValues: %s", parsedQuery, queryWithHiddenValues)
	return
}

func (acraCensor *AcraCensor) saveUnparsedQuery(query string) {
	if acraCensor.unparsedQueriesWriter != nil {
		acraCensor.unparsedQueriesWriter.WriteQuery(query)
	}
}
