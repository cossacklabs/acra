package handlers

import (
	"strings"
	"io/ioutil"
	"encoding/json"
	"os"
	"github.com/cossacklabs/acra/logging"
	log "github.com/sirupsen/logrus"
	"time"
	"os/signal"
	"syscall"
)

const MaxQueriesInChannel = 10
const TimeoutSecondsToSerialize = 1

type QueryCaptureHandler struct {
	Queries []QueryInfo
	filePath string
	logChannel chan QueryInfo
	signalToSerialize chan bool
}

type QueryInfo struct {
	RawQuery string
	IsForbidden bool
}

func NewQueryCaptureHandler(filePath string) (*QueryCaptureHandler, error) {

	var _, err = os.Stat(filePath)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(filePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
	}

	bufferBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var queries []QueryInfo

	if len(bufferBytes) != 0 {
		if err = json.Unmarshal(bufferBytes, &queries); err != nil{
			return nil, err
		}
	}

	logChannel := make(chan QueryInfo, MaxQueriesInChannel)
	signalToSerialize := make(chan bool)
	signalShutdown := make(chan os.Signal, 2)
	signal.Notify(signalShutdown, os.Interrupt, syscall.SIGTERM)

	//serialization signal
	go func() {
		for {
			time.Sleep(TimeoutSecondsToSerialize * time.Second)
			//timer finished. Close channel to inform that serialization should be performed
			signalToSerialize <- true
		}
	}()

	handler := &QueryCaptureHandler{}
	handler.filePath = filePath
	handler.Queries = queries
	handler.signalToSerialize = signalToSerialize
	handler.logChannel = logChannel

	//handling goroutine
	go func (){
		for {
			select {
			case <-signalToSerialize:
				err := handler.Serialize()
				if err != nil {
					log.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}

			case queryInfo, ok := <-handler.logChannel:
				if ok {
					bytes, err := json.Marshal(queryInfo)
					if err != nil {
						log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
					}

					f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
					if err != nil {
						log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
					}

					if _, err = f.WriteString("\n"); err != nil {
						log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
					}

					if _, err = f.Write(bytes); err != nil {
						log.WithError(ErrSingleQueryCaptureError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
					}
					f.Close()

				} else {
					//channel is unexpectedly closed
					log.WithError(ErrUnexpectedCaptureChannelClose).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}
			case <-signalShutdown:
				err := handler.Serialize()
				if err != nil {
					log.WithError(ErrComplexSerializationError).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCensorSecurityError)
				}
			default:
				//do nothing. This means that channel has no data to read yet
			}
		}
	}()




	return handler, nil
}

func (handler *QueryCaptureHandler) CheckQuery(query string) error {
	//skip already logged queries
	for _, queryInfo := range handler.Queries{
		if strings.EqualFold(queryInfo.RawQuery, query){
			return nil
		}
	}
	queryInfo := &QueryInfo{}
	queryInfo.RawQuery = query
	queryInfo.IsForbidden = false
	handler.Queries = append(handler.Queries, *queryInfo)

	handler.logChannel <- *queryInfo

	return nil
}

func (handler *QueryCaptureHandler) Reset() {
	handler.Queries = nil
}

func (handler *QueryCaptureHandler) GetAllInputQueries() []string{
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

	handler.signalToSerialize <- true
}

func (handler *QueryCaptureHandler) GetForbiddenQueries() []string{
	var forbiddenQueries []string
	for _, queryInfo := range handler.Queries {
		if queryInfo.IsForbidden == true{
			forbiddenQueries = append(forbiddenQueries, queryInfo.RawQuery)
		}
	}
	return forbiddenQueries
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