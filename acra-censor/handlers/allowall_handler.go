package handlers

import (
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
)

// AllowAllHandler allows any input query
type AllowAllHandler struct {
	logger *log.Entry
}

// NewAllowallHandler is a constructor for AllowAllHandler
func NewAllowallHandler() *AllowAllHandler {
	handler := &AllowAllHandler{logger: log.WithField("handler", "allowall")}
	return handler
}

// CheckQuery passes any input query
func (handler *AllowAllHandler) CheckQuery(sqlQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// allow any query and stop further checks
	handler.logger.Infof("Query has been allowed by Allowall handler")
	return false, nil
}

// Release is for compliance with QueryHandlerInterface
func (handler *AllowAllHandler) Release() {
	return
}
