package common

import (
	"bytes"
	"encoding/json"
	"github.com/cossacklabs/acra/logging"
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

// DefaultWriteQueryChannelSize defines size of channel used for writing input queries
const DefaultWriteQueryChannelSize = 50

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
	signalWriteQuery     chan string
	signalShutdown       chan os.Signal
	serializationTimeout time.Duration
	serializationTicker  *time.Ticker
	logger               *log.Entry
}

// NewFileQueryWriter creates QueryWriter instance
func NewFileQueryWriter(filePath string) (*QueryWriter, error) {
	// create writer
	writer := &QueryWriter{
		queryIndex:           0,
		mutex:                &sync.RWMutex{},
		serializationTimeout: DefaultSerializationTimeout,
		serializationTicker:  time.NewTicker(DefaultSerializationTimeout),
		logger:               log.WithField("internal_object", "querywriter"),
		signalBackgroundExit: make(chan bool),
		signalWriteQuery:     make(chan string, DefaultWriteQueryChannelSize),
		signalShutdown:       make(chan os.Signal, 2),
	}
	signal.Notify(writer.signalShutdown, os.Interrupt, syscall.SIGTERM)

	storage, err := NewFileLogStorage(filePath)
	if err != nil {
		writer.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
		return nil, err
	}
	writer.logStorage = storage

	// load existing queries
	err = writer.readStoredQueries()
	if err != nil {
		writer.logger.WithError(ErrCantReadQueriesFromStorageError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't create QueryWriter instance")
		writer.logStorage.Close()
		return nil, err
	}
	return writer, nil
}

// GetQueries returns copy of internal buffer
func (queryWriter *QueryWriter) GetQueries() []*QueryInfo {
	queryWriter.mutex.RLock()
	queriesCopy := queryWriter.Queries
	queryWriter.mutex.RUnlock()
	return queriesCopy
}

// WalkQueries walks through each query and perform some action on it
func (queryWriter *QueryWriter) WalkQueries(visitor func(query *QueryInfo) error) error {
	queryWriter.mutex.Lock()
	defer queryWriter.mutex.Unlock()
	for _, query := range queryWriter.Queries {
		if err := visitor(query); err != nil {
			return err
		}
	}
	return nil
}

// DumpQueries writes all queries into file
func (queryWriter *QueryWriter) DumpQueries() error {
	queryWriter.mutex.Lock()
	rawData := queryWriter.serializeQueries(queryWriter.Queries)
	queryWriter.mutex.Unlock()
	if err := queryWriter.logStorage.WriteAll(rawData); err != nil {
		queryWriter.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't dump queries to storage")
		return err
	}
	return nil
}

// Free dumps all Captured queries to file and resets captured queries list
func (queryWriter *QueryWriter) Free() {
	queryWriter.DumpQueries()
	queryWriter.signalBackgroundExit <- true
	queryWriter.reset()
}

// Start starts background logging of input queries. Should be called in separate goroutine
func (queryWriter *QueryWriter) Start() {
	for {
		select {
		case query := <-queryWriter.signalWriteQuery:
			queryWriter.captureQuery(query)
			break
		case <-queryWriter.serializationTicker.C:
			err := queryWriter.dumpBufferedQueries()
			if err != nil {
				queryWriter.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Can't dump buffered queries")
			}
			queryWriter.serializationTicker.Stop()
			queryWriter.serializationTicker = time.NewTicker(queryWriter.serializationTimeout)
			break
		case <-queryWriter.signalBackgroundExit:
			queryWriter.serializationTicker.Stop()
			err := queryWriter.logStorage.Close()
			if err != nil {
				queryWriter.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Error occurred on exit QueryWriter instance")
			}
			return
		case <-queryWriter.signalShutdown:
			queryWriter.serializationTicker.Stop()
			err := queryWriter.logStorage.Close()
			if err != nil {
				queryWriter.logger.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Errorln("Error occurred on shutdown QueryWriter instance")
			}
			return
		default:
			//do nothing. This means that channel has no data to read yet
		}
	}
}

// WriteQuery writes input query to captured queries list
func (queryWriter *QueryWriter) WriteQuery(query string) {
	select {
	case queryWriter.signalWriteQuery <- query:
		break
	default:
		queryWriter.logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError).Warningln("Too much input queries")
	}
}

func (queryWriter *QueryWriter) reset() {
	queryWriter.mutex.Lock()
	queryWriter.Queries = nil
	queryWriter.mutex.Unlock()
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

func (queryWriter *QueryWriter) captureQuery(query string) {
	//skip already captured queries
	for _, queryInfo := range queryWriter.Queries {
		if strings.EqualFold(queryInfo.RawQuery, query) {
			return
		}
	}
	queryInfo := &QueryInfo{}
	queryInfo.RawQuery = query
	queryInfo.IsForbidden = false
	queryWriter.Queries = append(queryWriter.Queries, queryInfo)
}
