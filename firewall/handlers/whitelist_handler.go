package handlers

import (
	"errors"
)

type WhitelistHandler struct {
	whiteQueries[] string
}

var ErrQueryNotInWhitelist = errors.New("query not in whitelist")

func(handler * WhitelistHandler) CheckQuery(query string) error {

	yes, _ := contains(handler.whiteQueries, query)
	if !yes {
		return ErrQueryNotInWhitelist
	}
	return nil
}

func(handler * WhitelistHandler) AddQueries(queries []string) {

	for _, query := range queries {
		handler.whiteQueries = append(handler.whiteQueries, query)
	}
	handler.whiteQueries = removeDuplicates(handler.whiteQueries)
}

func (handler * WhitelistHandler) RemoveQueries(queries []string) {

	for _, query := range handler.whiteQueries {
		yes, index := contains(handler.whiteQueries, query)
		if yes {
			handler.whiteQueries = append(handler.whiteQueries[:index], handler.whiteQueries[index+1:]...)
		}
	}
}

func (handler * WhitelistHandler) AddTables(tableNames []string){

}

func (handler * WhitelistHandler) RemoveTables(tableNames []string){

}