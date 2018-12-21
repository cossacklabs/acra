package handlers

import (
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/sqlparser"
     log "github.com/sirupsen/logrus"
)
type DenyallHandler struct {
	logger   *log.Entry
}


func NewDenyallHandler() *DenyallHandler {
	handler := &DenyallHandler{}
	handler.logger = log.WithField("handler", "denyall")
	return handler
}

func (handler *DenyallHandler) CheckQuery(sqlQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// deny any query and stop further checks
	handler.logger.Errorf("Query has been block by Denyall handler")
	return false, common.ErrDenyallQueries
}

func (handler *DenyallHandler) Release(){
	handler.logger = log.WithField("handler", "denyall")
}
