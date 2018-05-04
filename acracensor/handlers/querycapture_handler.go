package handlers

import (
	"strings"
	"io/ioutil"
	"encoding/json"
	"os"
)

type QueryCaptureHandler struct {
	Queries []QueryInfo
	filePath string
	occuredError *CaptureError

	logChannel chan QueryInfo
}

type QueryInfo struct {
	RawQuery string
	IsForbidden bool
}

type CaptureError struct {
	err error
	query *QueryInfo
}

func NewQueryCaptureHandler(filePath string) (*QueryCaptureHandler, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	err = file.Close()
	if err != nil {
		return nil, err
	}

	emptyQuery := &QueryInfo{RawQuery:"", IsForbidden:false}
	occuredError := &CaptureError{err:nil, query:emptyQuery}

	logChannel_ := make(chan QueryInfo)

	go func (){
		for {
			select {
			case queryInfo, gotQuery := <-logChannel_:
				if gotQuery {
					bytes, err := json.Marshal(queryInfo)
					if err != nil {
						occuredError.query = &queryInfo
						occuredError.err = err
					}

					f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
					if err != nil {
						occuredError.query = &queryInfo
						occuredError.err = err
					}

					defer f.Close()
					if _, err = f.WriteString("\n"); err != nil {
						occuredError.query = &queryInfo
						occuredError.err = err
					}

					if _, err = f.Write(bytes); err != nil {
						occuredError.query = &queryInfo
						occuredError.err = err
					}
				} else {
					//channel is closed
					return
				}
			default:
			}
		}
	}()

	return &QueryCaptureHandler{Queries:nil, filePath:filePath, occuredError: occuredError, logChannel:logChannel_}, nil
}

func (handler *QueryCaptureHandler) GetErrorQuery() string {
	return handler.occuredError.query.RawQuery
}

func (handler *QueryCaptureHandler) CheckQuery(query string) error {
	if handler.occuredError.err != nil{
		return handler.occuredError.err
	}

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

func (handler *QueryCaptureHandler) MarkQueryAsForbidden(query string) error {
	for index, queryInfo := range handler.Queries {
		if strings.EqualFold(query, queryInfo.RawQuery) {
			handler.Queries[index].IsForbidden = true
		}
	}
	return handler.Serialize()
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