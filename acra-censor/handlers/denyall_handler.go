package handlers

import (
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
)

// DenyallHandler denies any input query
type DenyallHandler struct {
	logger *log.Entry
}

// NewDenyallHandler is a constructor for DenyallHandler
func NewDenyallHandler() *DenyallHandler {
	handler := &DenyallHandler{logger: log.WithField("handler", "denyall")}
	return handler
}

// CheckQuery blocks any input query
func (handler *DenyallHandler) CheckQuery(sqlQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// deny any query and stop further checks
	handler.logger.Errorf("Query has been block by Denyall handler")
	return false, common.ErrDenyAllError
}

// Release is for compliance with QueryHandlerInterface
func (handler *DenyallHandler) Release() {
	return
}
