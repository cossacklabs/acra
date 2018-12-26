package common

import (
	"bytes"
	"encoding/json"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
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

// LogStorage defines basic storage that should be used by QueryWriter
type LogStorage interface {
	io.Closer
	ReadAll() ([]byte, error)
	WriteAll([]byte) error
	Append([]byte) error
}

// QueryWriter is a mechanism that provides dumping input queries in background.
// It can be used as separate component or as one of censor's handlers
type QueryWriter struct {
	Queries              []*QueryInfo
	logStorage           LogStorage
	queryIndex           int
	mutex                *sync.RWMutex
	signalBackgroundExit chan bool
	serializationTimeout time.Duration
	serializationTicker  *time.Ticker
	logger               *log.Entry
}

// NewFileQueryWriter creates QueryWriter instance
func NewFileQueryWriter(filePath string) (*QueryWriter, error) {
	// create writer
	writer := &QueryWriter{}
	storage, err := NewFileLogStorage(filePath)
	if err != nil {
		writer.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
	}
	writer.logStorage = storage
	writer.queryIndex = 0
	writer.mutex = &sync.RWMutex{}
	// signals
	signalShutdown := make(chan os.Signal, 2)
	signal.Notify(signalShutdown, os.Interrupt, syscall.SIGTERM)
	signalBackgroundExit := make(chan bool)
	writer.signalBackgroundExit = signalBackgroundExit

	writer.serializationTimeout = DefaultSerializationTimeout
	writer.serializationTicker = time.NewTicker(DefaultSerializationTimeout)
	writer.logger = log.WithField("internal_object", "querywriter")

	// read existing queries
	err = writer.readStoredQueries()
	if err != nil {
		writer.logger.WithError(ErrCantReadQueriesFromStorageError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
		writer.logStorage.Close()
		return nil, err
	}

	//handling goroutine
	go func() {
		for {
			select {
			case <-writer.serializationTicker.C:
				err := writer.dumpBufferedQueries()
				if err != nil {
					writer.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't dump buffered queries")
				}
				writer.serializationTicker.Stop()
				writer.serializationTicker = time.NewTicker(writer.serializationTimeout)
			case <-signalBackgroundExit:
				writer.serializationTicker.Stop()
				err := writer.logStorage.Close()
				if err != nil {
					writer.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Error occurred on exit QueryWriter instance")
				}
			case <-signalShutdown:
				writer.serializationTicker.Stop()
				err := writer.logStorage.Close()
				if err != nil {
					writer.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Error occurred on shutdown QueryWriter instance")
				}
				return
			default:
				//do nothing. This means that channel has no data to read yet
			}
		}
	}()
	return writer, nil
}

// DumpQueries writes all queries into file.
func (queryWriter *QueryWriter) DumpQueries() error {
	queryWriter.mutex.Lock()
	defer queryWriter.mutex.Unlock()

	rawData := queryWriter.serializeQueries(queryWriter.Queries)
	if err := queryWriter.logStorage.WriteAll(rawData); err != nil {
		queryWriter.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't dump queries to storage")
		return err
	}
	return nil
}

// Release dumps all Captured queries to file and resets Captured queries list.
func (queryWriter *QueryWriter) Release() {
	queryWriter.DumpQueries()
	queryWriter.signalBackgroundExit <- true
	queryWriter.reset()
}

func (queryWriter *QueryWriter) reset() {
	queryWriter.mutex.Lock()
	defer queryWriter.mutex.Unlock()

	queryWriter.Queries = nil
}

func (queryWriter *QueryWriter) readStoredQueries() error {
	q, err := queryWriter.deserializeQueries()
	if err != nil {
		queryWriter.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't read stored queries")
		return err
	}
	queryWriter.Queries = q
	return nil
}

func (queryWriter *QueryWriter) dumpBufferedQueries() error {
	queryWriter.mutex.Lock()
	defer queryWriter.mutex.Unlock()

	partialRawData := queryWriter.serializeQueries(queryWriter.Queries[queryWriter.queryIndex:])
	if err := queryWriter.logStorage.Append(partialRawData); err != nil {
		return err
	}
	queryWriter.queryIndex = len(queryWriter.Queries)
	return nil
}

func (queryWriter *QueryWriter) deserializeQueries() ([]*QueryInfo, error) {
	bufferBytes, err := queryWriter.logStorage.ReadAll()
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

// GetAllInputQueries returns a list of non-masked RawQueries.
func (queryWriter *QueryWriter) GetAllInputQueries() []string {
	queryWriter.mutex.RLock()
	defer queryWriter.mutex.RUnlock()

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
	queryWriter.mutex.Lock()
	defer queryWriter.mutex.Unlock()

	for index, queryInfo := range queryWriter.Queries {
		if strings.EqualFold(queryWithHiddenValues, queryInfo.RawQuery) {
			queryWriter.Queries[index].IsForbidden = true
		}
	}
}

// GetForbiddenQueries returns a list of non-masked forbidden RawQueries.
func (queryWriter *QueryWriter) GetForbiddenQueries() []string {
	queryWriter.mutex.RLock()
	defer queryWriter.mutex.RUnlock()

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
	queryWriter.mutex.Lock()
	defer queryWriter.mutex.Unlock()

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
	return true, nil
}
