package handlers

import (
	"strings"
	"io/ioutil"
	"encoding/json"
)

type LoggingHandler struct {
	Queries []QueryInfo
	filePath string
}

type QueryInfo struct {
	RawQuery string
	IsForbidden bool
}

func NewLoggingHandler (filePath string) *LoggingHandler {
	return &LoggingHandler{Queries:nil, filePath:filePath}
}

func (handler *LoggingHandler) CheckQuery(query string) error {
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
	handler.Serialize()
	return nil
}

func (handler *LoggingHandler) Reset() {
	handler.Queries = nil
}

func (handler *LoggingHandler) GetAllInputQueries() []string{
	var queries []string
	for _, queryInfo := range handler.Queries {
		queries = append(queries, queryInfo.RawQuery)
	}
	return queries
}

func (handler *LoggingHandler) MarkQueryAsForbidden(query string) {
	for index, queryInfo := range handler.Queries {
		if strings.EqualFold(query, queryInfo.RawQuery) {
			handler.Queries[index].IsForbidden = true
		}
	}
	handler.Serialize()
}

func (handler *LoggingHandler) GetForbiddenQueries() []string{
	var forbiddenQueries []string
	for _, queryInfo := range handler.Queries {
		if queryInfo.IsForbidden == true{
			forbiddenQueries = append(forbiddenQueries, queryInfo.RawQuery)
		}
	}
	return forbiddenQueries
}

func (handler *LoggingHandler) Serialize() error {
	jsonFile, err := json.Marshal(handler.Queries)
	err = ioutil.WriteFile(handler.filePath, jsonFile, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (handler *LoggingHandler) Deserialize() error {
	var bufferBytes []byte
	bufferBytes, err := ioutil.ReadFile(handler.filePath)
	if err != nil {
		return err
	}
	json.Unmarshal(bufferBytes, &handler.Queries)
	if err != nil {
		return err
	}
	return nil
}