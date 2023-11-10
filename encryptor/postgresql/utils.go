package postgresql

import (
	"bytes"
	"context"
	"errors"

	pg_query "github.com/pganalyze/pg_query_go/v4"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/utils"
)

var (
	errNotFoundtable          = errors.New("not found table for alias")
	errNotSupported           = errors.New("not supported type of sql node")
	errTableAlreadyMatched    = errors.New("aliased table name already matched")
	errAliasedTableNotMatched = errors.New("aliases table not matched")
	errEmptyTableExprs        = errors.New("empty table exprs")
)

// AliasToTableMap store table alias as key and table name as value
type AliasToTableMap map[string]string

// AliasedTableName store TableName and related As value together
type AliasedTableName struct {
	TableName string
	As        string
}

// NewAliasToTableMapFromTables create AliasToTableMap from slice of aliased tables
func NewAliasToTableMapFromTables(tables []*AliasedTableName) AliasToTableMap {
	qualifierMap := AliasToTableMap{}
	for _, table := range tables {
		if table.As == "" {
			qualifierMap[table.TableName] = table.TableName
		} else {
			qualifierMap[table.As] = table.TableName
		}
	}
	return qualifierMap
}

const (
	allColumnsName         = "*"
	placeholdersSettingKey = "bind_encryption_settings"
)

// ParseQuerySettings parse list of select query settings based on schemaStore
func ParseQuerySettings(ctx context.Context, statement *pg_query.SelectStmt, schemaStore config.TableSchemaStore) ([]*base.QueryDataItem, error) {
	columns, err := MapColumnsToAliases(statement, schemaStore)
	if err != nil {
		logrus.WithError(err).Errorln("Can't extract columns from SELECT statement")
		return nil, err
	}
	querySelectSettings := make([]*base.QueryDataItem, 0, len(columns))
	for _, data := range columns {
		if data != nil {
			if schema := schemaStore.GetTableSchema(data.Table); schema != nil {
				var setting *base.QueryDataItem = nil
				if data.Name == "*" {
					for _, name := range schema.Columns() {
						setting = nil
						if columnSetting := schema.GetColumnEncryptionSettings(name); columnSetting != nil {
							setting = base.NewQueryDataItem(columnSetting, data.Table, name, "")
						}
						querySelectSettings = append(querySelectSettings, setting)
					}
				} else {
					if columnSetting := schema.GetColumnEncryptionSettings(data.Name); columnSetting != nil {
						setting = base.NewQueryDataItem(columnSetting, data.Table, data.Name, data.Alias)
					}
					querySelectSettings = append(querySelectSettings, setting)
				}
				continue
			}
		}
		querySelectSettings = append(querySelectSettings, nil)
	}
	return querySelectSettings, nil
}

// MapColumnsToAliases parse slice of ColumnInfo from sqlparser.Select and config.TableSchemaStore
func MapColumnsToAliases(selectQuery *pg_query.SelectStmt, tableSchemaStore config.TableSchemaStore) ([]*base.ColumnInfo, error) {
	out := make([]*base.ColumnInfo, 0, len(selectQuery.GetTargetList()))

	var joinTables []string
	var joinAliases map[string]string

	if joinExp := selectQuery.FromClause[0].GetJoinExpr(); joinExp != nil {
		joinTables = make([]string, 0)
		joinAliases = make(map[string]string)

		if ok := parseJoinTablesInfo(joinExp, &joinTables, joinAliases); !ok {
			return nil, base.ErrUnsupportedExpression
		}
	}

	for _, node := range selectQuery.GetTargetList() {
		if target := node.GetResTarget(); target != nil {
			// processing queries like `select (select value from table2) from table1`
			// subquery should return only one value
			if val := target.GetVal(); val != nil && val.GetSubLink() != nil {
				if subSelect := val.GetSubLink().GetSubselect(); subSelect != nil && subSelect.GetSelectStmt() != nil {
					targetList := subSelect.GetSelectStmt().GetTargetList()
					if len(targetList) != 1 {
						return nil, base.ErrUnsupportedExpression
					}

					if val := targetList[0].GetResTarget().GetVal(); val != nil && val.GetColumnRef() != nil {
						if fields := val.GetColumnRef().GetFields(); len(fields) == 1 && fields[0].GetAStar() != nil {
							return nil, base.ErrUnsupportedExpression
						}
					}

					subColumn, err := MapColumnsToAliases(subSelect.GetSelectStmt(), tableSchemaStore)
					if err != nil {
						return nil, err
					}
					out = append(out, subColumn...)
					continue
				}
			}

			if val := target.GetVal(); val != nil && val.GetColumnRef() != nil {
				// handling the case select * from table1

				fields := val.GetColumnRef().GetFields()
				// select * from table => fields len is 1;
				// select t1.* from table t1 => fields len is 2; and second one is AStart
				if (len(fields) == 1 && fields[0].GetAStar() != nil) || (len(fields) == 2 && fields[1].GetAStar() != nil) {
					if len(joinTables) > 0 {
						if len(fields) == 2 {
							alias := fields[0].GetString_().GetSval()
							joinTable, ok := joinAliases[alias]
							if !ok {
								return nil, base.ErrUnsupportedExpression
							}
							out = append(out, &base.ColumnInfo{Table: joinTable, Name: allColumnsName, Alias: allColumnsName})
							continue
						}

						for i := len(joinTables) - 1; i >= 0; i-- {
							out = append(out, &base.ColumnInfo{Table: joinTables[i], Name: allColumnsName, Alias: allColumnsName})
						}
						continue
					}

					tableName, err := getFirstTableWithoutAlias(selectQuery.FromClause)
					if err == nil {
						out = append(out, &base.ColumnInfo{Table: tableName, Name: allColumnsName, Alias: allColumnsName})
					} else {
						if len(selectQuery.FromClause) == 1 {
							tableNameStr, err := getTableNameWithoutAliases(selectQuery.FromClause[0])
							if err != nil {
								return nil, err
							}
							out = append(out, &base.ColumnInfo{Table: tableNameStr, Name: allColumnsName, Alias: allColumnsName})
							continue
						}

						if len(fields) == 2 {
							alias := fields[0].GetString_().GetSval()
							tableNameStr, err := findTableName(alias, alias, selectQuery.FromClause)
							if err != nil {
								return nil, err
							}
							out = append(out, &base.ColumnInfo{Table: tableNameStr.Table, Name: allColumnsName, Alias: allColumnsName})
						}
					}
					continue
				}

				info, err := FindColumnInfo(selectQuery.GetFromClause(), val.GetColumnRef(), tableSchemaStore)
				if err == nil {
					out = append(out, &info)
					continue
				}
			}

			if val := target.GetVal(); val != nil && val.GetRowExpr() != nil {
				//TODO: potential syntax to select tuple select (id, phone_number), ssn from users;
				// add processing
				return nil, base.ErrUnsupportedExpression
			}

			out = append(out, nil)
		}
	}
	return out, nil
}

// FindColumnInfo get ColumnInfo from TableExprs, ColName  and  TableSchemaStore
func FindColumnInfo(fromClause []*pg_query.Node, colRef *pg_query.ColumnRef, schemaStore config.TableSchemaStore) (base.ColumnInfo, error) {
	var columnName, alias string
	var fields = colRef.GetFields()
	// select users.id from users - will contain two fields => one for alias, second for column;
	// select id from users - will contain only one filed for column
	if len(fields) > 2 || len(fields) == 0 {
		return base.ColumnInfo{}, base.ErrUnsupportedExpression
	}

	columnName = fields[0].GetString_().GetSval()
	if len(fields) == 2 {
		columnName = fields[1].GetString_().GetSval()
		alias = fields[0].GetString_().GetSval()
	}

	if alias == "" {
		columnTable, err := getMatchedTable(fromClause, colRef, schemaStore)
		if err != nil {
			return base.ColumnInfo{}, err
		}
		alias = columnTable
	}

	info, err := findTableName(alias, columnName, fromClause)
	if err != nil {
		return base.ColumnInfo{}, err
	}
	info.Alias = alias

	return info, nil
}

func getTableNameWithoutAliases(node *pg_query.Node) (string, error) {
	rangeVar := node.GetRangeVar()
	if rangeVar == nil {
		return "", errNotFoundtable
	}

	return rangeVar.GetRelname(), nil
}

func getMatchedTable(fromExpr []*pg_query.Node, colRef *pg_query.ColumnRef, tableSchemaStore config.TableSchemaStore) (string, error) {
	if len(fromExpr) == 0 {
		return "", errEmptyTableExprs
	}

	if joinExp := fromExpr[0].GetJoinExpr(); joinExp != nil {
		tableName, ok := getJoinFirstTableWithoutAlias(joinExp)
		if !ok {
			return "", errNotFoundtable
		}
		return tableName, nil
	}

	isTableColumn := func(tableSchema config.TableSchema, col *pg_query.Node) bool {
		for _, column := range tableSchema.Columns() {
			if column == col.GetString_().GetSval() {
				return true
			}
		}
		return false
	}

	var alisedName string
	for _, exp := range fromExpr {
		rangeVar := exp.GetRangeVar()

		tableSchema := tableSchemaStore.GetTableSchema(rangeVar.GetRelname())
		if tableSchema == nil {
			continue
		}

		if isTableColumn(tableSchema, colRef.GetFields()[0]) {
			getTableName := getAliasedName
			if rangeVar.GetAlias() == nil {
				getTableName = getNonAliasedName
			}

			tName, ok := getTableName(exp)
			if !ok {
				return "", base.ErrUnsupportedExpression
			}

			if alisedName != "" {
				logrus.WithField("alias", alisedName).Infoln("Ambiguous column found, several tables contain the same column")
				return "", errTableAlreadyMatched
			}

			alisedName = tName
		}
	}

	if alisedName == "" {
		return "", errAliasedTableNotMatched
	}

	return alisedName, nil
}

func getAliasedName(node *pg_query.Node) (string, bool) {
	if node.GetRangeVar() == nil {
		return "", false
	}

	if node.GetRangeVar().GetAlias() == nil {
		return "", false
	}

	return node.GetRangeVar().GetAlias().GetAliasname(), true
}

func getNonAliasedName(node *pg_query.Node) (string, bool) {
	if node.GetRangeVar() == nil {
		return "", false
	}

	if node.GetRangeVar().GetAlias() != nil {
		return "", false
	}

	return node.GetRangeVar().GetRelname(), true
}

func findTableName(alias, columnName string, expr any) (base.ColumnInfo, error) {
	// processing list of tables
	if val, ok := expr.([]*pg_query.Node); ok {
		// FROM table1, table2, join ....
		// search through list of tables by specific type of sql node (AliasedTableExpr, Join, ...)
		for _, tblExpr := range val {
			result, err := findTableName(alias, columnName, tblExpr)
			if err == nil {
				return result, nil
			}
		}
	} else if val, ok := expr.(*pg_query.Node); ok && val.GetRangeVar() != nil {
		rangeVar := val.GetRangeVar()
		// select users.id from users
		if alias == rangeVar.GetRelname() {
			return base.ColumnInfo{Name: columnName, Table: alias}, nil
		}

		// select usr.id from users usr
		if tableAlias := rangeVar.GetAlias(); tableAlias != nil && tableAlias.GetAliasname() == alias {
			return base.ColumnInfo{Name: columnName, Table: rangeVar.GetRelname(), Alias: alias}, nil
		}

		if alias != "" && rangeVar.GetAlias() == nil {
			if alias != rangeVar.GetRelname() {
				return base.ColumnInfo{}, errNotFoundtable
			}
		}
	} else if val, ok := expr.(*pg_query.Node); ok && val.GetJoinExpr() != nil {
		result, err := findTableName(alias, columnName, val.GetJoinExpr().GetLarg())
		if err == errNotFoundtable {
			return findTableName(alias, columnName, val.GetJoinExpr().GetRarg())
		}
		return result, err
	} else if val, ok := expr.(*pg_query.Node); ok && val.GetRangeSubselect() != nil {
		subSelect := val.GetRangeSubselect()
		selectStmt := subSelect.GetSubquery().GetSelectStmt()

		if subSelectAlias := subSelect.GetAlias(); subSelectAlias != nil && alias != "" {
			if alias != subSelectAlias.GetAliasname() {
				return base.ColumnInfo{}, errNotFoundtable
			}
		}

		alias := ""
		for _, targetItem := range selectStmt.GetTargetList() {
			resTarget := targetItem.GetResTarget()
			fields := resTarget.GetVal().GetColumnRef().GetFields()

			// select t1.col1
			if targetItem.GetResTarget().GetName() == "" {
				if len(fields) == 1 {
					// select col1
					if fields[0].GetString_().GetSval() == columnName {
						// find first table in FROM list
						firstTable, err := getFirstTableWithoutAlias(selectStmt.FromClause)
						if err != nil {
							continue
						}
						return base.ColumnInfo{Name: columnName, Table: firstTable}, nil
					}
				} else {
					aliasVal := fields[0].GetString_().GetSval()
					colNameVal := fields[1].GetString_().GetSval()
					// t1.col1 == col1 so we should find source name of t1.
					if fields[1].GetString_().GetSval() == columnName {
						return findTableName(aliasVal, colNameVal, selectStmt.FromClause)
					}
				}
				continue
			} else if resTarget.GetName() == alias || (alias == "" && resTarget.GetName() == columnName) {
				// select t1.col1 as columnName
				if len(fields) == 1 {
					firstTable, err := getFirstTableWithoutAlias(selectStmt.FromClause)
					if err != nil {
						return base.ColumnInfo{}, err
					}
					return findTableName(firstTable, fields[0].GetString_().GetSval(), selectStmt.FromClause)
				}
				return findTableName(fields[0].GetString_().GetSval(), fields[1].GetString_().GetSval(), selectStmt.FromClause)
			}
		}
	}

	return base.ColumnInfo{}, errNotFoundtable
}

// parseJoinTablesInfo recursively read and save sql join structure info, aliases map is used to save association between tables and its aliases,
// tables slice is used to collect certain order of tables (saved in reverse order of declaration).
// JoinTableExpr structure represent a recursive tree where RightExpr and LeftExpr are corresponded leaf node
// recursive processing starts from RightExpr leaf to the LeftExpr one, and when cast LeftExpr to AliasedTableExpr is successful
// it means that we reach last leaf in the tree.
func parseJoinTablesInfo(joinExp *pg_query.JoinExpr, tables *[]string, aliases map[string]string) bool {
	if larg := joinExp.GetLarg(); larg != nil && larg.GetRangeVar() != nil || larg.GetRangeSubselect() != nil {
		// here we reach the last leaf in the JoinTableExpr recursive tree, processing SHOULD be stopped in this block.
		// and we should process remaining RightExpr and LeftExpr leafs more before exit.
		ok := getRightJoinTableInfo(joinExp, tables, aliases)
		if !ok {
			return false
		}

		//	_, ok = aliased.Expr.(*sqlparser.Subquery)
		//	if ok {
		//		//  add subquery processing if needed
		//		return true
		//	}

		var tableName = larg.GetRangeVar().GetRelname()
		var alias = tableName

		if aliasNode := larg.GetRangeVar().GetAlias(); aliasNode != nil {
			alias = aliasNode.GetAliasname()
		}

		*tables = append(*tables, tableName)
		aliases[alias] = tableName
		return true

	}

	ok := getRightJoinTableInfo(joinExp, tables, aliases)
	if !ok {
		return false
	}

	if larg := joinExp.GetLarg(); larg != nil && larg.GetJoinExpr() != nil {
		return parseJoinTablesInfo(larg.GetJoinExpr(), tables, aliases)
	}

	return false
}

// getRightJoinTableInfo return tableName and its alias for right join table
// in case of more complex JOINs constructions like `JOIN (table1 AS t1 JOIN table2 AS t2 ON ... JOIN table3 ...) ON ...`
// represented by sqlparser.ParenTableExpr it runs parseJoinTablesInfo itself recursively to collect tableName and its alias info inside this block
func getRightJoinTableInfo(joinExp *pg_query.JoinExpr, tables *[]string, aliases map[string]string) bool {
	rarg := joinExp.GetRarg()
	if rarg != nil && rarg.GetJoinExpr() != nil {
		return parseJoinTablesInfo(rarg.GetJoinExpr(), tables, aliases)
	}

	if rarg != nil && rarg.GetRangeVar() == nil {
		return false
	}

	var tableName = rarg.GetRangeVar().GetRelname()
	var alias string
	if al := rarg.GetRangeVar().GetAlias(); al == nil {
		alias = tableName
	} else {
		alias = rarg.GetRangeVar().GetAlias().GetAliasname()
	}

	if _, ok := aliases[alias]; !ok {
		*tables = append(*tables, tableName)
		aliases[alias] = tableName
	}

	return true
}

// getFirstTableWithoutAlias search table name from "FROM" expression which has not any alias
// if more than one table specified without alias then return errNotFoundTable
func getFirstTableWithoutAlias(fromExpr []*pg_query.Node) (string, error) {
	if len(fromExpr) == 0 {
		return "", errEmptyTableExprs
	}

	if joinExp := fromExpr[0].GetJoinExpr(); joinExp != nil {
		tableName, ok := getJoinFirstTableWithoutAlias(joinExp)
		if !ok {
			return "", errNotFoundtable
		}
		return tableName, nil
	}

	var name string
	for _, node := range fromExpr {
		tName, ok := getNonAliasedName(node)
		if !ok {
			continue
		}
		if name != "" {
			return "", errors.New("more than 1 table without alias")
		}
		name = tName
	}
	if name == "" {
		return "", errNotFoundtable
	}
	return name, nil
}

// getJoinFirstTableWithoutAlias recursively process JoinTableExpr tree until it reaches the first table in JOIN declarations
// used to handle queries like this `select table1.column1, column2, column3 from table1 join table2 as t2` and match column2 to table1
func getJoinFirstTableWithoutAlias(joinExp *pg_query.JoinExpr) (string, bool) {
	if larg := joinExp.GetLarg(); larg != nil && larg.GetRangeVar() != nil {
		return getNonAliasedName(larg)
	}

	larg := joinExp.GetLarg()
	if larg == nil || larg.GetJoinExpr() == nil {
		return "", false
	}

	return getJoinFirstTableWithoutAlias(larg.GetJoinExpr())
}

// GetTablesWithAliases collect all tables from all update TableExprs which may be as subquery/table/join/etc
// collect only table names and ignore aliases for subqueries
func GetTablesWithAliases(tables []*pg_query.Node) []*AliasedTableName {
	var outputTables []*AliasedTableName
	for _, exp := range tables {
		if ranageVar := exp.GetRangeVar(); ranageVar != nil {
			var alias string
			if ranageVar.GetAlias() != nil {
				alias = ranageVar.GetAlias().GetAliasname()
			}
			outputTables = append(outputTables, &AliasedTableName{TableName: ranageVar.GetRelname(), As: alias})
		}

		if joinExp := exp.GetJoinExpr(); joinExp != nil {
			outputTables = append(outputTables, GetTablesWithAliases([]*pg_query.Node{joinExp.GetLarg(), joinExp.GetRarg()})...)
		}
	}
	return outputTables
}

// UpdateExpressionValue decode value from DB related string to binary format, call updateFunc, encode to DB string format and replace value in expression with new
func UpdateExpressionValue(ctx context.Context, expr *pg_query.A_Const, coder *PostgresqlPgQueryDBDataCoder, setting config.ColumnEncryptionSetting, updateFunc func(context.Context, []byte) ([]byte, error)) error {
	if sval := expr.GetSval(); sval != nil {
		rawData, err := coder.Decode(expr, setting)
		if err != nil {
			if err == utils.ErrDecodeOctalString || err == base.ErrUnsupportedExpression {
				logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCodingCantDecodeSQLValue).
					WithError(err).
					Warningln("Can't decode data with unsupported coding format or unsupported expression")
				return ErrUpdateLeaveDataUnchanged
			}
			return err
		}

		newData, err := updateFunc(ctx, rawData)
		if err != nil {
			return err
		}
		if len(newData) == len(rawData) && bytes.Equal(newData, rawData) {
			return ErrUpdateLeaveDataUnchanged
		}
		coded, err := coder.Encode(expr, newData, setting)
		if err != nil {
			return err
		}
		sval.Sval = string(coded)
	}

	return nil
}
