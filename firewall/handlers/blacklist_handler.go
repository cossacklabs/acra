package handlers

import (
	"errors"

)

type BlacklistHandler struct {
	blackQueries[] string
}

var ErrQueryInBlacklist = errors.New("query in blacklist")

func NewBlacklistHandler(blackQueries []string) (*BlacklistHandler, error) {

	uniqueBlackQueries := make([]string, len(blackQueries))
	copy(blackQueries, uniqueBlackQueries)
	removeDuplicates(&uniqueBlackQueries)

	return &BlacklistHandler{blackQueries:uniqueBlackQueries}, nil
}

func(handler * BlacklistHandler) CheckQuery(query string) error {

	yes, _ := contains(handler.blackQueries, query)
	if yes {
		return ErrQueryInBlacklist
	}
	return nil
}

func(handler * BlacklistHandler) AddQueriesToBlacklist(queries []string) {

	for _, query := range queries{
		handler.blackQueries = append(handler.blackQueries, query)
	}

	removeDuplicates(&handler.blackQueries)


}

func(handler * BlacklistHandler) RemoveQueriesFromBlacklist(queries []string){

	for _, query := range queries{
		yes, index := contains(handler.blackQueries, query)
		if yes {
			handler.blackQueries = append(handler.blackQueries[:index], handler.blackQueries[index+1:]...)
		}
	}
}