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
}

type QueryInfo struct {
	RawQuery string
	IsForbidden bool
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
	return &QueryCaptureHandler{Queries:nil, filePath:filePath}, nil
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
	return handler.Serialize()
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