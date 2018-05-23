package handlers

import (
	"encoding/json"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const MaxQueriesInChannel = 10
const DefaultSerializationTimeout = time.Second

type QueryCaptureHandler struct {
	Queries              []QueryInfo
	filePath             string
	logChannel           chan QueryInfo
	signalBackgroundExit chan bool
	serializationTimeout time.Duration
	serializationTicker  *time.Ticker
}
type QueryInfo struct {
	RawQuery    string
	IsForbidden bool
}

func NewQueryCaptureHandler(filePath string) (*QueryCaptureHandler, error) {
	var _, err = os.Stat(filePath)

	// create file if not exists
	if err != nil {
		if os.IsNotExist(err) {
			var file, err = os.Create(filePath)
			if err != nil {
				return nil, err
			}
			defer file.Close()
		} else {
			return nil, err
		}
	}

	bufferBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var queries []QueryInfo

	if len(bufferBytes) != 0 {
		if err = json.Unmarshal(bufferBytes, &queries); err != nil {
			return nil, err
		}
	}

	logChannel := make(chan QueryInfo, MaxQueriesInChannel)

	signalShutdown := make(chan os.Signal, 2)
	signal.Notify(signalShutdown, os.Interrupt, syscall.SIGTERM)

	signalBackgroundExit := make(chan bool)

	handler := &QueryCaptureHandler{}
	handler.filePath = filePath
	handler.Queries = queries
	handler.logChannel = logChannel
	handler.signalBackgroundExit = signalBackgroundExit
	handler.serializationTimeout = DefaultSerializationTimeout
	handler.serializationTicker = time.NewTicker(DefaultSerializationTimeout)

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
		return nil, err
	}

	//handling goroutine
	go func() {
		for {
			select {
			case <-handler.serializationTicker.C:
				err := handler.Serialize()
				if err != nil {
					log.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}
				handler.serializationTicker.Stop()
				handler.serializationTicker = time.NewTicker(handler.serializationTimeout)

			case queryInfo, ok := <-handler.logChannel:
				if ok {
					bytes, err := json.Marshal(queryInfo)
					if err != nil {
						log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
					}

					if _, err = f.WriteString("\n"); err != nil {
						log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
					}

					if _, err = f.Write(bytes); err != nil {
						log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
					}

				} else {
					//channel is unexpectedly closed
					log.WithError(ErrUnexpectedCaptureChannelClose).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}

			case <-signalBackgroundExit:
				handler.serializationTicker.Stop()
				f.Close()
				return

			case <-signalShutdown:
				handler.serializationTicker.Stop()
				f.Close()
				err := handler.Serialize()
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
func (handler *QueryCaptureHandler) CheckQuery(query string) error {
	//skip already captured queries
	for _, queryInfo := range handler.Queries {
		if strings.EqualFold(queryInfo.RawQuery, query) {
			return nil
		}
	}
	queryInfo := &QueryInfo{}
	queryInfo.RawQuery = query
	queryInfo.IsForbidden = false
	handler.Queries = append(handler.Queries, *queryInfo)

	select {
	case handler.logChannel <- *queryInfo: // channel is ok
	default: //channel is full
		log.Errorf("can't process too many queries")
	}

	return nil
}
func (handler *QueryCaptureHandler) Reset() {
	handler.Queries = nil
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

func (handler *QueryCaptureHandler) Serialize() error {
	jsonFile, err := json.Marshal(handler.Queries)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(handler.filePath, jsonFile, 0600)
}
func (handler *QueryCaptureHandler) Deserialize() error {
	var bufferBytes []byte
	bufferBytes, err := ioutil.ReadFile(handler.filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(bufferBytes, &handler.Queries)
}
