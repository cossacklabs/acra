package acracensor

import (
	log "github.com/sirupsen/logrus"
)

type AcraCensor struct {
	handlers []QueryHandlerInterface
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
