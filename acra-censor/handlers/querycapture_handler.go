package handlers

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bytes"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
)

// DefaultSerializationTimeout shows number of seconds after which captured queries are dumped to QueryCaptureLog file.
const DefaultSerializationTimeout = time.Second

// QueryCaptureHandler remembers all unique captured SQL queries,
// writes them to the QueryCaptureLog every serializationTimeout seconds.
type QueryCaptureHandler struct {
	Queries              []*QueryInfo
	BufferedQueries      []*QueryInfo
	filePath             string
	signalBackgroundExit chan bool
	serializationTimeout time.Duration
	serializationTicker  *time.Ticker
	logger               *log.Entry
}

// QueryInfo describes Query and if it was blocked by external source.
type QueryInfo struct {
	RawQuery    string `json:"raw_query"`
	IsForbidden bool   `json:"_blocked_by_web_config"`
}

// NewQueryCaptureHandler creates new QueryCaptureHandler, connected to QueryCaptureLog file at filePath.
func NewQueryCaptureHandler(filePath string) (*QueryCaptureHandler, error) {
	// open or create file, APPEND MODE
	openedFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.WithField("handler", "querycapture").WithError(ErrCantReadQueriesFromFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryCaptureHandler instance")
		return nil, err
	}
	// signals
	signalShutdown := make(chan os.Signal, 2)
	signal.Notify(signalShutdown, os.Interrupt, syscall.SIGTERM)
	signalBackgroundExit := make(chan bool)
	// create handler
	handler := &QueryCaptureHandler{}
	handler.filePath = filePath
	handler.signalBackgroundExit = signalBackgroundExit
	handler.serializationTimeout = DefaultSerializationTimeout
	handler.serializationTicker = time.NewTicker(DefaultSerializationTimeout)
	handler.logger = log.WithField("handler", "querycapture")
	// read existing queries from file
	err = handler.ReadAllQueriesFromFile()
	if err != nil {
		handler.logger.WithError(ErrCantReadQueriesFromFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryCaptureHandler instance")
		openedFile.Close()
		return nil, err
	}
	//handling goroutine
	go func() {
		for {
			select {
			case <-handler.serializationTicker.C:
				err := handler.DumpBufferedQueriesToFile(openedFile)
				if err != nil {
					handler.logger.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryCaptureHandler instance")
				}
				handler.serializationTicker.Stop()
				handler.serializationTicker = time.NewTicker(handler.serializationTimeout)

			case <-signalBackgroundExit:
				err := handler.FinishAndCloseFile(openedFile)
				if err != nil {
					handler.logger.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryCaptureHandler instance")
				}
				return

			case <-signalShutdown:
				err := handler.FinishAndCloseFile(openedFile)
				if err != nil {
					handler.logger.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryCaptureHandler instance")
				}
				return

			default:
				//do nothing. This means that channel has no data to read yet
			}
		}
	}()
	return handler, nil
}

// RedactAndCheckQuery redacts query first, then calls CheckQuery
func (handler *QueryCaptureHandler) RedactAndCheckQuery(query string) (bool, error) {
	_, queryWithHiddenValues, err := NormalizeAndRedactSQLQuery(query)
	if err != nil {
		return true, nil
	}
	return handler.CheckQuery(queryWithHiddenValues)
}

// CheckQuery returns "yes" if Query was already captured, no otherwise.
// Expects already redacted queries
func (handler *QueryCaptureHandler) CheckQuery(queryWithHiddenValues string) (bool, error) {
	//skip already captured queries
	for _, queryInfo := range handler.Queries {
		if strings.EqualFold(queryInfo.RawQuery, queryWithHiddenValues) {
			return true, nil
		}
	}
	queryInfo := &QueryInfo{}
	queryInfo.RawQuery = queryWithHiddenValues
	queryInfo.IsForbidden = false
	handler.Queries = append(handler.Queries, queryInfo)
	handler.BufferedQueries = append(handler.BufferedQueries, queryInfo)
	return true, nil
}

// Reset sets Captured queries list to nil.
func (handler *QueryCaptureHandler) Reset() {
	handler.Queries = nil
	handler.BufferedQueries = nil
}

// Release dumps all Captured queries to file and resets Captured queries list.
func (handler *QueryCaptureHandler) Release() {
	handler.signalBackgroundExit <- true
	handler.Reset()
}

// FinishAndCloseFile writes all Captured queries to file, and closes file.
// Returns error during writing / closing.
func (handler *QueryCaptureHandler) FinishAndCloseFile(openedFile *os.File) error {
	handler.serializationTicker.Stop()
	err := handler.DumpAllQueriesToFile()
	if err != nil {
		return err
	}
	return openedFile.Close()
}

// GetAllInputQueries returns a list of non-masked RawQueries.
func (handler *QueryCaptureHandler) GetAllInputQueries() []string {
	var queries []string
	for _, queryInfo := range handler.Queries {
		queries = append(queries, queryInfo.RawQuery)
	}
	return queries
}

// RedactAndMarkQueryAsForbidden redacts query first, then calls CheckQuery
func (handler *QueryCaptureHandler) RedactAndMarkQueryAsForbidden(query string) {
	_, queryWithHiddenValues, err := NormalizeAndRedactSQLQuery(query)
	if err != nil {
		return
	}
	handler.MarkQueryAsForbidden(queryWithHiddenValues)
}

// MarkQueryAsForbidden marks particular query as forbidden.
// It will be written to file on Stop, Reset or Release.
// Expects redacted query
func (handler *QueryCaptureHandler) MarkQueryAsForbidden(queryWithHiddenValues string) {
	for index, queryInfo := range handler.Queries {
		if strings.EqualFold(queryWithHiddenValues, queryInfo.RawQuery) {
			handler.Queries[index].IsForbidden = true
		}
	}
}

// GetForbiddenQueries returns a list of non-masked forbidden RawQueries.
func (handler *QueryCaptureHandler) GetForbiddenQueries() []string {
	var forbiddenQueries []string
	for _, queryInfo := range handler.Queries {
		if queryInfo.IsForbidden == true {
			forbiddenQueries = append(forbiddenQueries, queryInfo.RawQuery)
		}
	}
	return forbiddenQueries
}

// SetSerializationTimeout sets timeout of dumping captured queries to the file.
func (handler *QueryCaptureHandler) SetSerializationTimeout(timeout time.Duration) {
	handler.serializationTimeout = timeout
}

// GetSerializationTimeout gets timeout of dumping captured queries to the file.
func (handler *QueryCaptureHandler) GetSerializationTimeout() time.Duration {
	return handler.serializationTimeout
}

// DumpAllQueriesToFile writes all captures queries to file, returns IO error.
func (handler *QueryCaptureHandler) DumpAllQueriesToFile() error {
	// open or create file, NO APPEND
	f, err := os.OpenFile(handler.filePath, os.O_TRUNC|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		handler.logger.WithError(ErrCantOpenFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't dump queries to file")
		return err
	}
	// write all queries
	return handler.AppendQueries(handler.Queries, f)
}

// DumpBufferedQueriesToFile writes buffered queries to file (queries captured during serializationTimeout),
// returns IO error.
func (handler *QueryCaptureHandler) DumpBufferedQueriesToFile(openedFile *os.File) error {
	// nothing to dump
	if len(handler.BufferedQueries) == 0 {
		return nil
	}
	err := handler.AppendQueries(handler.BufferedQueries, openedFile)
	if err != nil {
		return err
	}
	// clean buffered queries only after successful write
	handler.BufferedQueries = nil
	return nil
}

// ReadAllQueriesFromFile loads all Queries from file, returns IO error.
func (handler *QueryCaptureHandler) ReadAllQueriesFromFile() error {
	q, err := ReadQueries(handler.filePath)
	if err != nil {
		handler.logger.WithError(ErrCantReadQueriesFromFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't read queries from file")
		return err
	}
	// read existing queries from file
	handler.Queries = q
	return nil
}

// AppendQueries appends some queries to the file, returns IO error.
func (handler *QueryCaptureHandler) AppendQueries(queries []*QueryInfo, openedFile *os.File) error {
	if len(queries) == 0 {
		return nil
	}
	lines := handler.SerializeQueries(queries)
	if _, err := openedFile.Write(lines); err != nil {
		return err
	}
	return nil
}

// SerializeQueries formats queries to JSON-line format before writing to file.
func (handler *QueryCaptureHandler) SerializeQueries(queries []*QueryInfo) []byte {
	var linesToAppend []byte
	var tempQueryInfo = &QueryInfo{}
	for _, queryInfo := range queries {
		tempQueryInfo.RawQuery = queryInfo.RawQuery
		tempQueryInfo.IsForbidden = queryInfo.IsForbidden
		jsonQueryInfo, err := json.Marshal(tempQueryInfo)
		if err != nil {
			handler.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQuerySerializeError).Errorln("Can't serialize stored queries")
		}
		if len(jsonQueryInfo) > 0 {
			jsonQueryInfo = append(jsonQueryInfo, '\n')
			linesToAppend = append(linesToAppend, jsonQueryInfo...)
		}
	}
	return linesToAppend
}

// ReadQueries reads list of queries from log file.
func ReadQueries(filePath string) ([]*QueryInfo, error) {
	bufferBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var queries []*QueryInfo
	if len(bufferBytes) != 0 {
		for _, line := range bytes.Split(bufferBytes, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var oneQuery QueryInfo
			if err = json.Unmarshal(line, &oneQuery); err != nil {
				return nil, err
			}
			queries = append(queries, &oneQuery)
		}
	}
	return queries, nil
}
