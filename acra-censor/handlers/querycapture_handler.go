package handlers

import (
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/sqlparser"
	"strings"
)

type QueryCapture struct {
	writer *common.QueryWriter
}

func NewQueryCapture(filePath string) (*QueryCapture, error) {
	queryCaptureHandler := &QueryCapture{}
	writer, err := common.NewFileQueryWriter(filePath)
	if err != nil {
		return nil, err
	}
	queryCaptureHandler.writer = writer
	return queryCaptureHandler, nil
}

func (handler *QueryCapture) Start() {
	handler.writer.Start()
}

// CheckQuery sends query to internal writer to save
func (handler *QueryCapture) CheckQuery(sqlQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// skip unparsed queries
	if parsedQuery == nil {
		return true, nil
	}
	handler.writer.WriteQuery(sqlQuery)
	return true, nil
}

// Release frees all resources
func (handler *QueryCapture) Release() {
	handler.writer.Free()
}

// DumpQueries
func (handler *QueryCapture) DumpQueries() error {
	err := handler.writer.DumpQueries()
	if err != nil {
		return err
	}
	return nil
}

// MarkQueryAsForbidden marks particular query as forbidden.
// Expects redacted query
func (handler *QueryCapture) MarkQueryAsForbidden(query string) error {
	_, queryWithHiddenValues, _, err := common.HandleRawSQLQuery(query)
	if err != nil {
		return err
	}
	queries := handler.writer.GetQueries()
	for index, queryInfo := range queries {
		if strings.EqualFold(queryWithHiddenValues, queryInfo.RawQuery) {
			newQueryInfo := &common.QueryInfo{}
			newQueryInfo.RawQuery = queryWithHiddenValues
			newQueryInfo.IsForbidden = true
			handler.writer.SetQuery(newQueryInfo, index)
		}
	}
	return nil
}

// GetForbiddenQueries returns a list of non-masked forbidden RawQueries.
func (handler *QueryCapture) GetForbiddenQueries() []string {
	queries := handler.writer.GetQueries()
	var forbiddenQueries []string
	for _, queryInfo := range queries {
		if queryInfo.IsForbidden == true {
			forbiddenQueries = append(forbiddenQueries, queryInfo.RawQuery)
		}
	}
	return forbiddenQueries
}
