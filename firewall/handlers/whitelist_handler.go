package handlers

import (
	"errors"
)

type WhitelistHandler struct {
	whiteQueries[] string
}

var ErrQueryNotInWhitelist = errors.New("query not in whitelist")

func NewWhitelistHandler(whiteQueries []string) (*WhitelistHandler, error) {

	uniqueWhiteQueries := make([]string, len(whiteQueries))
	copy(whiteQueries, uniqueWhiteQueries)
	removeDuplicates(&uniqueWhiteQueries)

	return &WhitelistHandler{whiteQueries:uniqueWhiteQueries}, nil
}

func(handler * WhitelistHandler) CheckQuery(query string) error {

	yes, _ := contains(handler.whiteQueries, query)
	if !yes {
		return ErrQueryNotInWhitelist
	}
	return nil
}

func(handler * WhitelistHandler) AddQueriesToWhitelist(queries []string) {

	for _, query := range queries {
		handler.whiteQueries = append(handler.whiteQueries, query)
	}
	removeDuplicates(&handler.whiteQueries)
}

func (handler * WhitelistHandler) RemoveQueriesFromWhitelist(queries []string) {

	for _, query := range handler.whiteQueries {
		yes, index := contains(handler.whiteQueries, query)
		if yes {
			handler.whiteQueries = append(handler.whiteQueries[:index], handler.whiteQueries[index+1:]...)
		}
	}
}