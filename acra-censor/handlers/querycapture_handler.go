package handlers

import (
	"github.com/cossacklabs/acra/acra-censor/common"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
	"strings"
)

// QueryCaptureHandler provides logging mechanism of censor
type QueryCaptureHandler struct {
	writer *common.QueryWriter
	logger *log.Entry
	parser *sqlparser.Parser
}

// NewQueryCaptureHandler is a constructor of QueryCaptureHandler instance
func NewQueryCaptureHandler(filePath string, parser *sqlparser.Parser) (*QueryCaptureHandler, error) {
	queryCaptureHandler := &QueryCaptureHandler{
		logger: log.WithField("handler", "query-capture"),
		parser: parser,
	}
	writer, err := common.NewFileQueryWriter(filePath)
	if err != nil {
		return nil, err
	}
	queryCaptureHandler.writer = writer
	return queryCaptureHandler, nil
}

// Start starts logging in background
func (handler *QueryCaptureHandler) Start() {
	handler.writer.Start()
}

// CheckQuery sends query to internal writer to save
func (handler *QueryCaptureHandler) CheckQuery(sqlQuery string, parsedQuery sqlparser.Statement) (bool, error) {
	// skip unparsed queries
	if parsedQuery == nil {
		return true, nil
	}
	handler.writer.WriteQuery(sqlQuery)
	return true, nil
}

// Release frees all resources
func (handler *QueryCaptureHandler) Release() {
	handler.writer.Free()
}

// DumpQueries saves all queries stored in memory of internal writer instance.
// Expected to be called after marking queries as forbidden
func (handler *QueryCaptureHandler) DumpQueries() error {
	err := handler.writer.DumpQueries()
	if err != nil {
		handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't dump queries")
		return err
	}
	return nil
}

// MarkQueryAsForbidden marks particular query as forbidden.
// Expects redacted query
func (handler *QueryCaptureHandler) MarkQueryAsForbidden(query string) error {
	_, queryWithHiddenValues, _, err := handler.parser.HandleRawSQLQuery(query)
	if err != nil {
		handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQueryParseError).Errorln("Can't mark query as forbidden")
		return err
	}
	err = handler.writer.WalkQueries(func(queryInfo *common.QueryInfo) error {
		if strings.EqualFold(queryInfo.RawQuery, queryWithHiddenValues) {
			queryInfo.IsForbidden = true
		}
		return nil
	})
	return err
}

// GetForbiddenQueries returns a list of non-masked forbidden RawQueries.
func (handler *QueryCaptureHandler) GetForbiddenQueries() []string {
	var forbiddenQueries []string
	err := handler.writer.WalkQueries(func(queryInfo *common.QueryInfo) error {
		if queryInfo.IsForbidden {
			forbiddenQueries = append(forbiddenQueries, queryInfo.RawQuery)
		}
		return nil
	})
	if err != nil {
		handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorWriterMemoryError).Errorln("Can't get forbidden queries")
	}
	return forbiddenQueries
}
