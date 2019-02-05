package handlers

import (
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
)

// DenyAllHandler denies any input query
type DenyAllHandler struct {
	logger *log.Entry
}

// NewDenyallHandler is a constructor for DenyAllHandler
func NewDenyallHandler() *DenyAllHandler {
	handler := &DenyAllHandler{logger: log.WithField("handler", "denyall")}
	return handler
}

// CheckQuery blocks any input query
func (handler *DenyAllHandler) CheckQuery(sqlQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// deny any query and stop further checks
	handler.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryIsNotAllowed).Errorf("Query has been block by Denyall handler")
	return false, common.ErrDenyAllError
}

// Release is for compliance with QueryHandlerInterface
func (handler *DenyAllHandler) Release() {
	return
}
