package handlers

import (
	"errors"
)

type WhitelistHandler struct {
	whiteQueries[] string
}

var ErrQueryNotInWhitelist = errors.New("query not in whitelist")

func NewWhitelistHandler(whiteQueries []string) (*WhitelistHandler, error) {

	return &WhitelistHandler{whiteQueries:whiteQueries}, nil
}

func(handler * WhitelistHandler) CheckQuery(query string) error {
	if !handler.contains(query) {
		return ErrQueryNotInWhitelist
	}
	return nil
}

func(handler * WhitelistHandler) AddQueriesToWhitelist(queries []string) {

	for index := 0; index < len(queries); index++ {
		handler.whiteQueries = append(handler.whiteQueries, queries[index])
	}
	removeDuplicates(&handler.whiteQueries)
}

func (handler * WhitelistHandler) RemoveQueriesFromWhitelist(queries []string) {
	for index := 0; index < len(queries); index++ {
		if handler.contains(queries[index]){
			//https://github.com/golang/go/wiki/SliceTricks
			handler.whiteQueries[index] = handler.whiteQueries[len(handler.whiteQueries) - 1]
			handler.whiteQueries = handler.whiteQueries[:len(handler.whiteQueries) - 1]
		}
	}
}

func(handler * WhitelistHandler) contains(query string) bool {
	for _, whiteQuery := range handler.whiteQueries {
		if whiteQuery == query {
			return true
		}
	}
	return false
}