package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"strings"
)

type WhitelistHandler struct {
	whiteQueries[] string
	allowedTables[] string
}

var ErrQueryNotInWhitelist = errors.New("query not in whitelist")

func(handler * WhitelistHandler) CheckQuery(query string) error {

	if len(handler.whiteQueries) != 0 {
		yes, _ := contains(handler.whiteQueries, query)
		if !yes {
			return ErrQueryNotInWhitelist
		}
	}

	if len(handler.allowedTables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			return err
		}

		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			allowedTablesCounter := 0
			for _, allowedTable := range handler.allowedTables {
				for _, table := range parsedQuery.From{
					if strings.EqualFold(sqlparser.String(table.(*sqlparser.AliasedTableExpr).Expr), allowedTable) {
						allowedTablesCounter++
					}
				}
			}
			if allowedTablesCounter != len(parsedQuery.From){
				return ErrAccessToForbiddenTable
			}

		case *sqlparser.Insert:

			tableIsAllowed := false
			for _, allowedTable := range handler.allowedTables {
				if strings.EqualFold(parsedQuery.Table.Name.String(), allowedTable) {
					tableIsAllowed = true
				}
			}
			if !tableIsAllowed{
				return ErrAccessToForbiddenTable
			}

		case *sqlparser.Update:

		}
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
	for _, tableName := range tableNames{
		handler.allowedTables = append(handler.allowedTables, tableName)
	}

	handler.allowedTables = removeDuplicates(handler.allowedTables)
}

func (handler * WhitelistHandler) RemoveTables(tableNames []string){
	for _, query := range tableNames{
		yes, index := contains(handler.allowedTables, query)
		if yes {
			handler.allowedTables = append(handler.allowedTables[:index], handler.allowedTables[index+1:]...)
		}
	}
}