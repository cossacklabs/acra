package acracensor

import (
	"github.com/cossacklabs/acra/acra-censor/handlers"
	log "github.com/sirupsen/logrus"
)

type AcraCensor struct {
	handlers         []QueryHandlerInterface
	ignoreParseError bool
}

func (acraCensor *AcraCensor) AddHandler(handler QueryHandlerInterface) {
	acraCensor.handlers = append(acraCensor.handlers, handler)
}

func (acraCensor *AcraCensor) RemoveHandler(handler QueryHandlerInterface) {
	for index, handlerFromRange := range acraCensor.handlers {
		if handlerFromRange == handler {
			acraCensor.handlers = append(acraCensor.handlers[:index], acraCensor.handlers[index+1:]...)
		}
	}
}

func (acraCensor *AcraCensor) ReleaseAll() {
	for _, handler := range acraCensor.handlers {
		handler.Release()
	}
}

func (acraCensor *AcraCensor) HandleQuery(query string) error {
	for _, handler := range acraCensor.handlers {
		continueHandling, err := handler.CheckQuery(query)
		if err != nil {
			if err == handlers.ErrQuerySyntaxError && acraCensor.ignoreParseError {
				log.WithError(err).Infof("parsing error on query (first %v symbols): %s", handlers.LogQueryLength, handlers.TrimStringToN(query, handlers.LogQueryLength))
				continue
			}
			log.Errorf("Forbidden query: '%s'", query)
			return err
		} else {
			if !continueHandling {
				return nil
			}
		}
	}
	log.Infof("Allowed query: '%s'", query)
	return nil
}
