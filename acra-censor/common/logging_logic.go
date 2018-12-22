package common

import (
	"bytes"
	"encoding/json"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// DefaultSerializationTimeout defines a default ticker' timeout
const DefaultSerializationTimeout = time.Second

// QueryInfo defines format of exporting query into file
type QueryInfo struct {
	RawQuery    string `json:"raw_query"`
	IsForbidden bool   `json:"_blacklisted_by_web_config"`
}

// QueryWriter is a mechanism that provides dumping stored queries into file in background
type QueryWriter struct {
	filePath             string
	Queries              []*QueryInfo
	BufferedQueries      []*QueryInfo
	signalBackgroundExit chan bool
	serializationTimeout time.Duration
	serializationTicker  *time.Ticker
	logger               *log.Entry
}

// NewQueryWriter creates QueryWriter instance
func NewQueryWriter(filePath string) (*QueryWriter, error) {
	// open or create file, APPEND MODE
	openedFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.WithField("internal_object", "querywriter").WithError(ErrCantReadQueriesFromFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
		return nil, err
	}

	// signals
	signalShutdown := make(chan os.Signal, 2)
	signal.Notify(signalShutdown, os.Interrupt, syscall.SIGTERM)
	signalBackgroundExit := make(chan bool)

	// create handler
	handler := &QueryWriter{}
	handler.filePath = filePath
	handler.signalBackgroundExit = signalBackgroundExit

	handler.serializationTimeout = DefaultSerializationTimeout
	handler.serializationTicker = time.NewTicker(DefaultSerializationTimeout)
	handler.logger = log.WithField("internal_object", "querywriter")

	// read existing queries from file
	err = handler.readAllQueriesFromFile()
	if err != nil {
		handler.logger.WithError(ErrCantReadQueriesFromFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
		openedFile.Close()
		return nil, err
	}

	//handling goroutine
	go func() {
		for {
			select {
			case <-handler.serializationTicker.C:
				err := handler.dumpBufferedQueriesToFile(openedFile)
				if err != nil {
					handler.logger.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
				}
				handler.serializationTicker.Stop()
				handler.serializationTicker = time.NewTicker(handler.serializationTimeout)

			case <-signalBackgroundExit:
				err := handler.finishAndCloseFile(openedFile)
				if err != nil {
					handler.logger.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
				}
				return

			case <-signalShutdown:
				err := handler.finishAndCloseFile(openedFile)
				if err != nil {
					handler.logger.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
				}
				return

			default:
				//do nothing. This means that channel has no data to read yet
			}
		}
	}()
	return handler, nil
}

// SetSerializationTimeout sets timeout of dumping captured queries to the file.
func (queryWriter *QueryWriter) SetSerializationTimeout(timeout time.Duration) {
	queryWriter.serializationTimeout = timeout
}

// GetSerializationTimeout gets timeout of dumping captured queries to the file.
func (queryWriter *QueryWriter) GetSerializationTimeout() time.Duration {
	return queryWriter.serializationTimeout
}

// DumpAllQueriesToFile writes stored queries into file.
func (queryWriter *QueryWriter) DumpAllQueriesToFile() error {
	// open or create file, NO APPEND
	f, err := os.OpenFile(queryWriter.filePath, os.O_TRUNC|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		queryWriter.logger.WithError(ErrCantOpenFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't dump queries to file")
		return err
	}
	// write all queries
	return queryWriter.appendQueries(queryWriter.Queries, f)
}

// Release dumps all Captured queries to file and resets Captured queries list.
func (queryWriter *QueryWriter) Release() {
	queryWriter.signalBackgroundExit <- true
	queryWriter.reset()
}

func (queryWriter *QueryWriter) reset() {
	queryWriter.Queries = nil
	queryWriter.BufferedQueries = nil
}

func (queryWriter *QueryWriter) readAllQueriesFromFile() error {
	q, err := readQueries(queryWriter.filePath)
	if err != nil {
		queryWriter.logger.WithError(ErrCantReadQueriesFromFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't read queries from file")
		return err
	}
	// read existing queries from file
	queryWriter.Queries = q
	return nil
}

func readQueries(filePath string) ([]*QueryInfo, error) {
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

func (queryWriter *QueryWriter) dumpBufferedQueriesToFile(openedFile *os.File) error {
	// nothing to dump
	if len(queryWriter.BufferedQueries) == 0 {
		return nil
	}
	err := queryWriter.appendQueries(queryWriter.BufferedQueries, openedFile)
	if err != nil {
		return err
	}
	// clean buffered queries only after successful write
	queryWriter.BufferedQueries = nil
	return nil
}

func (queryWriter *QueryWriter) appendQueries(queries []*QueryInfo, openedFile *os.File) error {
	if len(queries) == 0 {
		return nil
	}
	lines := queryWriter.serializeQueries(queries)
	if _, err := openedFile.Write(lines); err != nil {
		return err
	}
	return nil
}

func (queryWriter *QueryWriter) serializeQueries(queries []*QueryInfo) []byte {
	var linesToAppend []byte
	var tempQueryInfo = &QueryInfo{}
	for _, queryInfo := range queries {
		tempQueryInfo.RawQuery = queryInfo.RawQuery
		tempQueryInfo.IsForbidden = queryInfo.IsForbidden
		jsonQueryInfo, err := json.Marshal(tempQueryInfo)
		if err != nil {
			queryWriter.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorQuerySerializeError).Errorln("Can't serialize stored queries")
		}
		if len(jsonQueryInfo) > 0 {
			jsonQueryInfo = append(jsonQueryInfo, '\n')
			linesToAppend = append(linesToAppend, jsonQueryInfo...)
		}
	}
	return linesToAppend
}

func (queryWriter *QueryWriter) finishAndCloseFile(openedFile *os.File) error {
	queryWriter.serializationTicker.Stop()
	err := queryWriter.DumpAllQueriesToFile()
	if err != nil {
		return err
	}
	return openedFile.Close()
}

// GetAllInputQueries returns a list of non-masked RawQueries.
func (queryWriter *QueryWriter) GetAllInputQueries() []string {
	var queries []string
	for _, queryInfo := range queryWriter.Queries {
		queries = append(queries, queryInfo.RawQuery)
	}
	return queries
}

// RedactAndMarkQueryAsForbidden redacts query first, then calls CheckQuery
func (queryWriter *QueryWriter) RedactAndMarkQueryAsForbidden(query string) {
	_, queryWithHiddenValues, _, err := HandleRawSQLQuery(query)
	if err != nil {
		return
	}
	queryWriter.MarkQueryAsForbidden(queryWithHiddenValues)
}

// MarkQueryAsForbidden marks particular query as forbidden.
// It will be written to file on Stop, Reset or Release.
// Expects redacted query
func (queryWriter *QueryWriter) MarkQueryAsForbidden(queryWithHiddenValues string) {
	for index, queryInfo := range queryWriter.Queries {
		if strings.EqualFold(queryWithHiddenValues, queryInfo.RawQuery) {
			queryWriter.Queries[index].IsForbidden = true
		}
	}
}

// GetForbiddenQueries returns a list of non-masked forbidden RawQueries.
func (queryWriter *QueryWriter) GetForbiddenQueries() []string {
	var forbiddenQueries []string
	for _, queryInfo := range queryWriter.Queries {
		if queryInfo.IsForbidden == true {
			forbiddenQueries = append(forbiddenQueries, queryInfo.RawQuery)
		}
	}
	return forbiddenQueries
}

// RedactAndCheckQuery redacts query first, then calls CheckQuery
func (queryWriter *QueryWriter) RedactAndCheckQuery(query string) (bool, error) {
	_, queryWithHiddenValues, parsedQuery, err := HandleRawSQLQuery(query)
	if err != nil {
		return true, nil
	}
	return queryWriter.CheckQuery(queryWithHiddenValues, parsedQuery)
}

// CheckQuery returns "yes" if Query was already captured, no otherwise.
// Expects already redacted queries
func (queryWriter *QueryWriter) CheckQuery(queryWithHiddenValues string, parsedQuery sqlparser.Statement) (bool, error) {
	_ = parsedQuery

	//skip already captured queries
	for _, queryInfo := range queryWriter.Queries {
		if strings.EqualFold(queryInfo.RawQuery, queryWithHiddenValues) {
			return true, nil
		}
	}
	queryInfo := &QueryInfo{}
	queryInfo.RawQuery = queryWithHiddenValues
	queryInfo.IsForbidden = false
	queryWriter.Queries = append(queryWriter.Queries, queryInfo)
	queryWriter.BufferedQueries = append(queryWriter.BufferedQueries, queryInfo)
	return true, nil
}
