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
	yes, _ := handler.contains(query)
	if yes {
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

	for i := 0; i < len(queries); i++ {
		yes, index := handler.contains(queries[i])
		if yes {
			handler.blackQueries = append(handler.blackQueries[:index], handler.blackQueries[index+1:]...)
		}
	}
}

func(handler * BlacklistHandler) contains(query string) (bool, int) {

	var index int
	for _, blackQuery := range handler.blackQueries {
		if blackQuery == query {

			return true, index
		}
		index++
	}
	return false, 0
}