package handlers

import (
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
)
type AllowallHandler struct {
	logger   *log.Entry
}


func NewAllowallHandler() *AllowallHandler {
	handler := &AllowallHandler{}
	handler.logger = log.WithField("handler", "allowall")
	return handler
}

func (handler *AllowallHandler) CheckQuery(sqlQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// allow any query and stop further checks
	handler.logger.Infof("Query has been allowed by Allowall handler")
	return false, nil
}

func (handler *AllowallHandler) Release(){
	handler.logger = log.WithField("handler", "allowall")
}