package handlers

import (
	"errors"
	"github.com/xwb1989/sqlparser"

)

type BlacklistHandler struct {
	blackQueries    [] string
	forbiddenTables [] string
}

var ErrQueryInBlacklist = errors.New("query in blacklist")
var ErrForbiddenTableDetected = errors.New("query tries to access forbidden table")



func(handler * BlacklistHandler) CheckQuery(query string) error {

	parsedQuery, err := sqlparser.Parse(query)
	if err != nil {
		return err
	}

	switch parsedQuery := parsedQuery.(type) {
	case *sqlparser.Select:

		for _, forbiddenTable := range handler.forbiddenTables {

			for _, table := range parsedQuery.From{
				if sqlparser.String(table.(*sqlparser.AliasedTableExpr)) == forbiddenTable{
					return ErrForbiddenTableDetected
				}
			}
		}

	case *sqlparser.Insert:
		for _, forbiddenTable := range handler.forbiddenTables {
			if parsedQuery.Table.Name.String() == forbiddenTable{
				return ErrForbiddenTableDetected
			}
		}

	case *sqlparser.Update:
		for _, forbiddenTable := range handler.forbiddenTables {
			err = parsedQuery.TableExprs.WalkSubtree(func(sqlNode sqlparser.SQLNode)(bool, error) {
				if sqlparser.GetTableName(sqlNode.(*sqlparser.AliasedTableExpr).Expr).String() == forbiddenTable {
					return false, ErrForbiddenTableDetected
				}
				return true, nil
			})

			if err == ErrForbiddenTableDetected{
				return err
			}
		}

	}


	//Check that query is not in blacklist
	yes, _ := contains(handler.blackQueries, query)
	if yes {
		return ErrQueryInBlacklist
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
