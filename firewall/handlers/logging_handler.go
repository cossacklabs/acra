package handlers

import (
	"strings"
	"io/ioutil"
	"encoding/json"
)

type LoggingHandler struct {
	Queries []QueryInfo
}

type QueryInfo struct {
	rawQuery string
	isForbidden bool
}

func (handler *LoggingHandler) CheckQuery(query string) error {

	//skip already logged queries
	for _, queryInfo := range handler.Queries{
		if strings.EqualFold(queryInfo.rawQuery, query){
			return nil
		}
	}

	queryInfo := &QueryInfo{}
	queryInfo.rawQuery = query
	queryInfo.isForbidden = false
	handler.Queries = append(handler.Queries, *queryInfo)

	return nil
}

func (handler *LoggingHandler) Reset() {
	handler.Queries = nil
}

func (handler *LoggingHandler) GetAllInputQueries() []string{
	var queries []string
	for _, queryInfo := range handler.Queries {
		queries = append(queries, queryInfo.rawQuery)
	}
	return queries
}

func (handler *LoggingHandler) MarkQueryAsForbidden(query string) {
	for index, queryInfo := range handler.Queries {
		if strings.EqualFold(query, queryInfo.rawQuery) {
			handler.Queries[index].isForbidden = true
		}
	}
}

func (handler *LoggingHandler) GetForbiddenQueries() []string{
	var forbiddenQueries []string
	for _, queryInfo := range handler.Queries {
		if queryInfo.isForbidden == true{
			forbiddenQueries = append(forbiddenQueries, queryInfo.rawQuery)
		}
	}
	return forbiddenQueries
}

func (handler *LoggingHandler) SaveToFile(path string) error {
	jsonFile, err := json.Marshal(handler.Queries)

	err = ioutil.WriteFile(path, jsonFile, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (handler *LoggingHandler) LoadFromFile(path string) error {
	var bufferBytes []byte
	bufferBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	json.Unmarshal(bufferBytes, &handler.Queries)
	if err != nil {
		return err
	}
	return nil
}