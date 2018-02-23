package handlers

import (
	"errors"
)

type BlacklistHandler struct {
	blackQueries[] string
}

var ErrQueryInBlacklist = errors.New("query in blacklist")

func NewBlacklistHandler(blackQueries []string) (*BlacklistHandler, error) {

	return &BlacklistHandler{blackQueries:blackQueries}, nil
}

func(handler * BlacklistHandler) CheckQuery(query string) error {
	if handler.contains(query) {
		return ErrQueryInBlacklist
	}
	return nil
}

func(handler * BlacklistHandler) AddQueriesToBlacklist(queries []string) {

	for index := 0; index < len(queries); index++ {
		handler.blackQueries = append(handler.blackQueries, queries[index])
	}
	removeDuplicates(&handler.blackQueries)
}

func(handler * BlacklistHandler) RemoveQueriesFromBlacklist(queries []string){
	for index := 0; index < len(queries); index++ {
		if handler.contains(queries[index]){
			//handler.blackQueries[index] = handler.blackQueries[len(handler.blackQueries) - 1]
			//handler.blackQueries = handler.blackQueries[:len(handler.blackQueries) - 1]
			handler.blackQueries = append(handler.blackQueries[:index], handler.blackQueries[index + 1:]...)
		}
	}
}

func(handler * BlacklistHandler) contains(query string) bool {
	for _, blackQuery := range handler.blackQueries {
		if blackQuery == query {
			return true
		}
	}
	return false
}