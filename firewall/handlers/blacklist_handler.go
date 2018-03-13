package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"
	"strings"
)

type BlacklistHandler struct {
	blackQueries    [] string
	forbiddenTables [] string
}

var ErrQueryInBlacklist = errors.New("query in blacklist")
var ErrAccessToForbiddenTable = errors.New("query tries to access forbidden table")


func(handler * BlacklistHandler) CheckQuery(query string) error {

	if len(handler.blackQueries) != 0 {
		//Check that query is not in blacklist
		yes, _ := contains(handler.blackQueries, query)
		if yes {
			return ErrQueryInBlacklist
		}
	}


	if len(handler.forbiddenTables) != 0 {
		parsedQuery, err := sqlparser.Parse(query)
		if err != nil {
			return err
		}

		switch parsedQuery := parsedQuery.(type) {
		case *sqlparser.Select:
			for _, forbiddenTable := range handler.forbiddenTables {
				for _, table := range parsedQuery.From{
					if strings.EqualFold(sqlparser.String(table.(*sqlparser.AliasedTableExpr).Expr), forbiddenTable) {
						return ErrAccessToForbiddenTable
					}
				}
			}

		case *sqlparser.Insert:
			for _, forbiddenTable := range handler.forbiddenTables {
				if strings.EqualFold(parsedQuery.Table.Name.String(), forbiddenTable) {
					return ErrAccessToForbiddenTable
				}
			}

		case *sqlparser.Update:

		}
	}

	return nil
}

func(handler * BlacklistHandler) AddQueries(queries []string) {

	for _, query := range queries{
		handler.blackQueries = append(handler.blackQueries, query)
	}

	handler.blackQueries = removeDuplicates(handler.blackQueries)
}

func(handler * BlacklistHandler) RemoveQueries(queries []string){

	for _, query := range queries{
		yes, index := contains(handler.blackQueries, query)
		if yes {
			handler.blackQueries = append(handler.blackQueries[:index], handler.blackQueries[index+1:]...)
		}
	}
}

func (handler * BlacklistHandler) AddTables(tableNames []string){

	for _, tableName := range tableNames{
		handler.forbiddenTables = append(handler.forbiddenTables, tableName)
	}

	handler.forbiddenTables = removeDuplicates(handler.forbiddenTables)
}

func (handler * BlacklistHandler) RemoveTables(tableNames []string) {

	for _, query := range tableNames{
		yes, index := contains(handler.forbiddenTables, query)
		if yes {
			handler.forbiddenTables = append(handler.forbiddenTables[:index], handler.forbiddenTables[index+1:]...)
		}
	}
}
