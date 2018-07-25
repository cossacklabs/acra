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
	queryWithHiddenValues, err := handlers.RedactSQLQuery(query)
	if err == handlers.ErrQuerySyntaxError && acraCensor.ignoreParseError {
		acraCensor.logger.WithError(err).Infof("Parsing error on query (first %v symbols): %s", handlers.LogQueryLength, handlers.TrimStringToN(queryWithHiddenValues, handlers.LogQueryLength))
	}
	for _, handler := range acraCensor.handlers {
		continueHandling, err := handler.CheckQuery(query)
		if err != nil {
			if err == handlers.ErrQuerySyntaxError && acraCensor.ignoreParseError {
				acraCensor.logger.WithError(err).Infof("Parsing error on query (first %v symbols): %s", handlers.LogQueryLength, handlers.TrimStringToN(queryWithHiddenValues, handlers.LogQueryLength))
				continue
			}
			acraCensor.logger.Errorf("Forbidden query: '%s'", queryWithHiddenValues)
			return err
		} else {
			if !continueHandling {
				return nil
			}
		}
	}
	acraCensor.logger.Infof("Allowed query: '%s'", queryWithHiddenValues)
	return nil
}
