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

const DefaultSerializationTimeout = time.Second

func trimToN(query string, n int) string {
	if len(query) <= n {
		return query
	}
	return query[:n]
}

type QueryCaptureHandler struct {
	Queries              []QueryInfo
	BufferedQueries      []QueryInfo
	filePath             string
	signalBackgroundExit chan bool
	serializationTimeout time.Duration
	serializationTicker  *time.Ticker
}
type QueryInfo struct {
	RawQuery    string
	IsForbidden bool
}

func NewQueryCaptureHandler(filePath string) (*QueryCaptureHandler, error) {
	// open or create file
	openedFile, err := os.OpenFile(filePath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
		return nil, err
	}
	defer openedFile.Close()

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

	// read existing queries from file
	handler.ReadAllQueriesFromFile()


	//handling goroutine
	go func() {
		for {
			select {
			case <-handler.serializationTicker.C:
				err := handler.DumpBufferedQueriesToFile(openedFile)
				if err != nil {
					log.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}
				handler.serializationTicker.Stop()
				handler.serializationTicker = time.NewTicker(handler.serializationTimeout)

			// TODO: how to remove duplicate code?
			case <-signalBackgroundExit:
				handler.serializationTicker.Stop()
				err := handler.DumpAllQueriesToFile()
				if err != nil {
					log.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}
				return

			case <-signalShutdown:
				handler.serializationTicker.Stop()
				err := handler.DumpAllQueriesToFile()
				if err != nil {
					log.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}
				return

			default:
				//do nothing. This means that channel has no data to read yet
			}
		}
	}()

	return handler, nil
}
func (handler *QueryCaptureHandler) CheckQuery(query string) (bool, error) {
	//skip already captured queries
	for _, queryInfo := range handler.Queries {
		if strings.EqualFold(queryInfo.RawQuery, query) {
			return true, nil
		}
	}
	queryInfo := &QueryInfo{}
	queryInfo.RawQuery = query
	queryInfo.IsForbidden = false
	handler.Queries = append(handler.Queries, *queryInfo)
	handler.BufferedQueries = append(handler.BufferedQueries, *queryInfo)

	return true, nil
}
func (handler *QueryCaptureHandler) Reset() {
	handler.Queries = nil
	handler.BufferedQueries = nil
}

func (handler *QueryCaptureHandler) Release() {
	handler.Reset()
	handler.signalBackgroundExit <- true
}

func (handler *QueryCaptureHandler) GetAllInputQueries() []string {
	var queries []string
	for _, queryInfo := range handler.Queries {
		queries = append(queries, queryInfo.RawQuery)
	}
	return queries
}
func (handler *QueryCaptureHandler) MarkQueryAsForbidden(query string) {
	for index, queryInfo := range handler.Queries {
		if strings.EqualFold(query, queryInfo.RawQuery) {
			handler.Queries[index].IsForbidden = true
		}
	}
}
func (handler *QueryCaptureHandler) GetForbiddenQueries() []string {
	var forbiddenQueries []string
	for _, queryInfo := range handler.Queries {
		if queryInfo.IsForbidden == true {
			forbiddenQueries = append(forbiddenQueries, queryInfo.RawQuery)
		}
	}
	return forbiddenQueries
}

func (handler *QueryCaptureHandler) SetSerializationTimeout(timeout time.Duration) {
	handler.serializationTimeout = timeout
}

func (handler *QueryCaptureHandler) GetSerializationTimeout() time.Duration {
	return handler.serializationTimeout
}

func (handler *QueryCaptureHandler) DumpAllQueriesToFile() error {
	// open or create file
	f, err := os.OpenFile(handler.filePath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.WithError(ErrCantOpenFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError)
		return err
	}
	defer f.Close()

	// write all queries
	allQueries := append(handler.Queries, handler.BufferedQueries...)
	return AppendQueries(allQueries, f)
}

func (handler *QueryCaptureHandler) DumpBufferedQueriesToFile(openedFile *os.File) error {
	// write buffered queries
	err := AppendQueries(handler.BufferedQueries, openedFile)
	if err != nil {
		return err
	}

	// clean buffered queries
	handler.BufferedQueries = nil
	return nil
}

func (handler *QueryCaptureHandler) ReadAllQueriesFromFile() error {
	q, err := ReadQueries(handler.filePath)
	if err != nil {
		log.WithError(ErrCantReadQueriesFromFileError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorIOError)
		return err
	}

	// read existing queries from file
	handler.Queries = q
	return nil
}

func AppendQueries(queries []QueryInfo, openedFile *os.File) error {
	lines, err := SerializeQueries(queries)
	if err != nil {
		return err
	}

	if _, err := openedFile.Write(lines); err != nil {
		return err
	}

	return nil
}


func SerializeQueries(queries []QueryInfo) ([]byte, error) {
	var linesToAppend []byte
	for _, queryInfo := range queries {
		jsonQueryInfo, err := json.Marshal(queryInfo)
		if err != nil {
			return nil, err
		}
		if len(jsonQueryInfo) > 0 {
			linesToAppend = append(linesToAppend, "\n"...)
			linesToAppend = append(linesToAppend, jsonQueryInfo...)
		}
	}
	return linesToAppend, nil

}

func ReadQueries(filePath string) ([]QueryInfo, error) {
	bufferBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var queries []QueryInfo

	if len(bufferBytes) != 0 {
		for _, line := range bytes.Split(bufferBytes, []byte{'\n'}) {
			var oneQuery QueryInfo
			if err = json.Unmarshal(line, &oneQuery); err != nil {
				return nil, err
			}
			queries = append(queries, oneQuery)
		}
	}
	return queries, nil
}