package mysql

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
)

// ErrStatementAlreadyInRegistry represent an error that prepared statement already exist in session registry
var (
	ErrStatementNotPresentInRegistry = errors.New("prepared statement not present in registry")
	// ErrUnsupportedQueryType represent error related unsupported Query type
	ErrUnsupportedQueryType = errors.New("unsupported Query type")
)

// PreparedStatementsQuery QueryDataEncryptor process PostgreSQL SQL PreparedStatement
type PreparedStatementsQuery struct {
	proxyHandler        *Handler
	parser              *sqlparser.Parser
	encryptor           encryptor.DataEncryptor
	schemaStore         config.TableSchemaStore
	coder               encryptor.DBDataCoder
	querySelectSettings []*encryptor.QueryDataItem
}

// NewMySQLPreparedStatementsQuery create new QueryDataEncryptor to handle SQL PreparedStatement in the following format
// https://dev.mysql.com/doc/refman/8.0/en/sql-prepared-statements.html
func NewMySQLPreparedStatementsQuery(proxyHandler *Handler, parser *sqlparser.Parser, schemaStore config.TableSchemaStore) *PreparedStatementsQuery {
	return &PreparedStatementsQuery{
		proxyHandler,
		parser,
		nil,
		schemaStore,
		&encryptor.MysqlDBDataCoder{},
		nil,
	}
}

// SetDataEncryptor set encryptor.DataEncryptor
func (e *PreparedStatementsQuery) SetDataEncryptor(dataEncryptor encryptor.DataEncryptor) {
	e.encryptor = dataEncryptor
}

// ID returns name of this QueryObserver.
func (e *PreparedStatementsQuery) ID() string {
	return "PreparedStatementsQuery"
}

// OnColumn return new encryption setting context if info exist, otherwise column data and passed context will be returned
func (e *PreparedStatementsQuery) OnColumn(ctx context.Context, data []byte) (context.Context, []byte, error) {
	columnInfo, ok := base.ColumnInfoFromContext(ctx)
	if ok {
		// return context with encryption setting
		if columnInfo.Index() < len(e.querySelectSettings) {
			selectSetting := e.querySelectSettings[columnInfo.Index()]
			if selectSetting != nil {

				logging.GetLoggerFromContext(ctx).WithField("column_index", columnInfo.Index()).WithField("column", selectSetting.ColumnName()).Debugln("Set encryption setting")
				return encryptor.NewContextWithEncryptionSetting(ctx, selectSetting.Setting()), data, nil
			}
		}

	}
	return ctx, data, nil
}

// OnQuery processes query text before database sees it.
func (e *PreparedStatementsQuery) OnQuery(ctx context.Context, query base.OnQueryObject) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnQuery")
	e.querySelectSettings = nil

	parsedQuery, err := query.Statement()
	if err != nil {
		logrus.WithError(err).Debugln("Can't parse SQL statement")
		return query, false, nil
	}

	switch processQuery := parsedQuery.(type) {
	case *sqlparser.Prepare:
		return e.onPrepare(ctx, processQuery)
	case *sqlparser.Set:
		return e.onSet(ctx, processQuery)
	case *sqlparser.Execute:
		return e.onExecute(ctx, processQuery)
	case *sqlparser.DeallocatePrepare:
		return e.onDeallocate(ctx, processQuery)
	default:
		return query, false, nil
	}
}

func (e *PreparedStatementsQuery) onPrepare(ctx context.Context, prepareQuery *sqlparser.Prepare) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Prepare")

	var preparedStatementName = prepareQuery.PreparedStatementName.String()

	// MySQL allows create statements many time, so just log in case of already registered
	if _, err := e.proxyHandler.registry.StatementByID(preparedStatementName); err == nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement already stored in registry")
		return nil, false, nil
	}

	stmt, ok := prepareQuery.PreparedStatementQuery.(sqlparser.Statement)
	if !ok {
		if ident, ok := prepareQuery.PreparedStatementQuery.(sqlparser.TableIdent); ok {
			logrus.Debugln("Got PreparedStatement with SetArg query")
			setArgStmt, err := e.proxyHandler.registry.StatementByID(ident.String())
			if err != nil {
				logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
					WithError(err).Errorln("SetArg PreparedStatement not in registry")
				return nil, false, err
			}

			querySettings, _ := e.proxyHandler.registry.QuerySettingsByID(ident.String())

			// add new PreparedStatement using different name
			// 1. SET @s = 'SELECT SQRT(POW(?,2) + POW(?,2)) AS hypotenuse';
			//    - store in registry with name @s
			// 2. On PREPARE stmt2 FROM @s;
			//    - reset with name stmt2 to use in execute statement
			// 3. On EXECUTE stmt2 USING @a, @b;
			//    - read by stmt2 name
			var preparedStatement = NewPreparedStatement(0, 0, setArgStmt.QueryText(), setArgStmt.Query())
			preparedStatement.name = preparedStatementName
			e.proxyHandler.registry.AddStatement(preparedStatement)
			e.proxyHandler.registry.AddQuerySettings(preparedStatementName, querySettings)
		}

		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			Errorln("Error to cast PreparedStatementQuery to sqlparser.Statement")
		return nil, false, nil
	}

	changedObject, changed, err := e.onQuery(ctx, preparedStatementName, stmt)
	if err != nil {
		return nil, false, err
	}

	if changed {
		if err := e.updateChangedQuery(changedObject); err != nil {
			return nil, false, err
		}

		changedStatement, _ := changedObject.Statement()

		changedPreparedQuery, ok := changedStatement.(sqlparser.PreparedQuery)
		if !ok {
			logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithError(err).Errorln("Failed to cast changedStatement to PreparedQuery")
			return nil, false, err
		}

		prepareQuery.PreparedStatementQuery = changedPreparedQuery
	}

	logrus.WithField("prepared_name", preparedStatementName).Debug("Registered new prepared statement")
	return base.NewOnQueryObjectFromStatement(prepareQuery, e.parser), changed, nil
}

func (e *PreparedStatementsQuery) onSet(ctx context.Context, setQuery *sqlparser.Set) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Set Query")
	var changedRes bool

	for _, arg := range setQuery.Exprs {
		sqlVal, ok := arg.Expr.(*sqlparser.SQLVal)
		if !ok {
			logrus.Debugln("Set Arg is not SQLVal statement")
			continue
		}

		// Prepared statement could be supply the text of the statement as a user variable:
		// SET @s = 'SELECT SQRT(POW(?,2) + POW(?,2)) AS hypotenuse';
		// PREPARE stmt2 FROM @s;
		// https://dev.mysql.com/doc/refman/8.0/en/sql-prepared-statements.html
		//TODO: potentially we can get it from sqlparser directly
		prepareQuery, err := sqlparser.NewPreparedQueryFromString(string(sqlVal.Val))
		if err == nil && prepareQuery != nil {
			var stmt = prepareQuery.(sqlparser.Statement)

			logrus.Debugln("New PreparedStatement from Set Arg")
			changedObject, changed, err := e.onQuery(ctx, arg.Name.String(), stmt)
			if err != nil {
				return nil, false, err
			}

			if changed {
				if err := e.updateChangedQuery(changedObject); err != nil {
					return nil, false, err
				}

				sqlVal.Val = []byte(changedObject.Query())
				changedRes = changed
			}
			continue
		}

		delim := e.schemaStore.GetDatabaseSettings().GetMySQLDatabaseSettings().
			GetPreparedStatementsSetArgDelimiter()
		splits := strings.Split(arg.Name.String(), delim)
		if len(splits) == 1 {
			continue
		}

		tableName := strings.TrimPrefix(splits[0], "@")
		columnName := splits[1]

		schema := e.schemaStore.GetTableSchema(tableName)
		if schema == nil {
			logrus.Debugf("Hasn't schema for table in SET query %s", tableName)
			return nil, false, nil
		}

		columnSetting := schema.GetColumnEncryptionSettings(columnName)
		if columnSetting == nil {
			logrus.Debugf("No column encryption setting %s", columnName)
			return nil, false, nil
		}

		accessContext := base.AccessContextFromContext(ctx)
		clientID := columnSetting.ClientID()
		if len(clientID) > 0 {
			logrus.WithField("client_id", string(clientID)).Debugln("Encrypt with specific ClientID for column")
		} else {
			logrus.WithField("client_id", string(accessContext.GetClientID())).Debugln("Encrypt with ClientID from connection")
			clientID = accessContext.GetClientID()
		}

		rawData, err := e.coder.Decode(sqlVal, columnSetting)
		if err != nil {
			return nil, false, nil
		}

		encryptedData, err := e.encryptor.EncryptWithClientID(clientID, rawData, columnSetting)
		if err != nil {
			return nil, false, err
		}

		if !bytes.Equal(encryptedData, sqlVal.Val) {
			output := make([]byte, hex.EncodedLen(len(encryptedData)))
			hex.Encode(output, encryptedData)

			sqlVal.Val = output
			sqlVal.Type = sqlparser.HexVal
			changedRes = true
		}
	}

	return base.NewOnQueryObjectFromStatement(setQuery, e.parser), changedRes, nil
}

func (e *PreparedStatementsQuery) onExecute(ctx context.Context, executeQuery *sqlparser.Execute) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Execute")

	var preparedStatementName = executeQuery.PreparedStatementName.String()

	_, err := e.proxyHandler.registry.StatementByID(preparedStatementName)
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement not present in registry")
		return nil, false, ErrStatementNotPresentInRegistry
	}

	querySetting, ok := e.proxyHandler.registry.QuerySettingsByID(preparedStatementName)
	if ok {
		logrus.Debugln("Set query settings from registry")
		e.querySelectSettings = querySetting
	}

	return base.NewOnQueryObjectFromStatement(executeQuery, e.parser), true, nil
}

func (e *PreparedStatementsQuery) onDeallocate(ctx context.Context, deallocateQuery *sqlparser.DeallocatePrepare) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Deallocate")

	var preparedStatementName = deallocateQuery.PreparedStatementName.String()

	if _, err := e.proxyHandler.registry.StatementByID(deallocateQuery.PreparedStatementName.String()); err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement not present in registry")
		return nil, false, ErrStatementNotPresentInRegistry
	}

	e.proxyHandler.registry.DeleteStatementByID(preparedStatementName)
	return nil, false, nil
}

func (e *PreparedStatementsQuery) onQuery(ctx context.Context, preparedStatementName string, stmt sqlparser.Statement) (base.OnQueryObject, bool, error) {
	var query = sqlparser.String(stmt)
	var preparedStatement = NewPreparedStatement(0, 0, query, stmt)

	preparedStatement.name = preparedStatementName
	e.proxyHandler.registry.AddStatement(preparedStatement)

	queryObj := base.NewOnQueryObjectFromQuery(query, e.parser)
	changedObject, changed, err := e.proxyHandler.queryObserverManager.OnQuery(ctx, queryObj)
	if err != nil {
		logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).Errorln("Error occurred in OnQuery handler")
		return nil, false, err
	}

	switch query := stmt.(type) {
	case *sqlparser.Select:
		querySetting, err := e.parseQuerySettings(ctx, query)
		if err != nil {
			logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).Errorln("Failed to parse querySettings for select in Prepare")
			return nil, false, err
		}
		e.proxyHandler.registry.AddQuerySettings(preparedStatementName, querySetting)
	}

	return changedObject, changed, nil
}

// OnBind just a stub method of QueryObserver of  PreparedStatementsQuery
func (e *PreparedStatementsQuery) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnBind")
	return values, false, nil
}

func filterTableExpressions(statement sqlparser.Statement) (sqlparser.TableExprs, error) {
	switch query := statement.(type) {
	case *sqlparser.Select:
		return query.From, nil
	case *sqlparser.Update:
		return query.TableExprs, nil
	case *sqlparser.Delete:
		return query.TableExprs, nil
	case *sqlparser.Insert:
		// only support INSERT INTO table2 SELECT * FROM test_table WHERE data1='somedata' syntax for INSERTs
		if selectInInsert, ok := query.Rows.(*sqlparser.Select); ok {
			return selectInInsert.From, nil
		}
		return nil, ErrUnsupportedQueryType
	default:
		return nil, ErrUnsupportedQueryType
	}
}

func getColumnSetting(column *sqlparser.ColName, tableName string, schemaStore config.TableSchemaStore) config.ColumnEncryptionSetting {
	schema := schemaStore.GetTableSchema(tableName)
	if schema == nil {
		return nil
	}
	// Also leave out those columns which are not searchable.
	columnName := column.Name.ValueForConfig()
	return schema.GetColumnEncryptionSettings(columnName)
}

func getWhereStatements(stmt sqlparser.Statement) ([]*sqlparser.Where, error) {
	var whereStatements []*sqlparser.Where
	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		switch nodeType := node.(type) {
		case *sqlparser.Where:
			whereStatements = append(whereStatements, nodeType)
		case sqlparser.JoinCondition:
			whereStatements = append(whereStatements, &sqlparser.Where{
				Type: "on",
				Expr: nodeType.On,
			})
		}
		return true, nil
	}, stmt)
	return whereStatements, err
}

func (e *PreparedStatementsQuery) filterSearchableComparisons(statement sqlparser.Statement) []SearchableExprItem {
	tableExps, err := filterTableExpressions(statement)
	if err != nil {
		logrus.Debugln("Unsupported search query")
		return nil
	}

	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := getWhereStatements(statement)
	if err != nil {
		logrus.WithError(err).Debugln("Failed to extract WHERE clauses")
		return nil
	}

	var searchableExprs []SearchableExprItem
	for _, whereExpr := range whereExprs {
		comparisonExprs, err := e.filterColumnEqualComparisonExprs(whereExpr, tableExps)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to extract comparison expressions")
			return nil
		}
		searchableExprs = append(searchableExprs, comparisonExprs...)
	}

	return searchableExprs
}

func (e *PreparedStatementsQuery) updateChangedQuery(changedObject base.OnQueryObject) error {
	changedStatement, err := changedObject.Statement()
	if err != nil {
		return err
	}

	items := e.filterSearchableComparisons(changedStatement)
	if len(items) == 0 {
		return nil
	}

	hashSize := []byte(fmt.Sprintf("%d", hmac.GetDefaultHashSize()))
	for _, item := range items {
		if !item.Setting.IsSearchable() {
			continue
		}

		item.Expr.Right = &sqlparser.SubstrExpr{
			Name: &sqlparser.ColName{
				Name: sqlparser.NewColIdentUnquote("?"),
			},
			From: sqlparser.NewIntVal([]byte{'1'}),
			To:   sqlparser.NewIntVal(hashSize),
		}
	}

	return nil
}

// SearchableExprItem represent the filtered value found by SearchableQueryFilter
type SearchableExprItem struct {
	Expr    *sqlparser.ComparisonExpr
	Setting config.ColumnEncryptionSetting
}

// filterColumnEqualComparisonExprs return only <ColName> = <VALUE> or <ColName> != <VALUE> or <ColName> <=> <VALUE> expressions
func (e *PreparedStatementsQuery) filterColumnEqualComparisonExprs(stmt sqlparser.SQLNode, tableExpr sqlparser.TableExprs) ([]SearchableExprItem, error) {
	var exprs []SearchableExprItem

	err := sqlparser.Walk(func(node sqlparser.SQLNode) (kontinue bool, err error) {
		comparisonExpr, ok := node.(*sqlparser.ComparisonExpr)
		if !ok {
			return true, nil
		}

		lColumn, ok := comparisonExpr.Left.(*sqlparser.SubstrExpr)
		if !ok {
			return true, nil
		}

		rColumn, ok := comparisonExpr.Right.(*sqlparser.SQLVal)
		if !ok {
			return true, nil
		}

		if !strings.HasPrefix(string(rColumn.Val), ":v") {
			return true, nil
		}

		columnInfo, err := encryptor.FindColumnInfo(tableExpr, lColumn.Name, e.schemaStore)
		if err != nil {
			return true, nil
		}

		lColumnSetting := getColumnSetting(lColumn.Name, columnInfo.Table, e.schemaStore)
		if lColumnSetting == nil {
			return true, nil
		}

		if !lColumnSetting.IsSearchable() {
			return true, nil
		}

		exprs = append(exprs, SearchableExprItem{
			Expr:    comparisonExpr,
			Setting: lColumnSetting,
		})
		return true, nil
	}, stmt)
	return exprs, err
}

func (e *PreparedStatementsQuery) parseQuerySettings(ctx context.Context, statement *sqlparser.Select) ([]*encryptor.QueryDataItem, error) {
	columns, err := encryptor.MapColumnsToAliases(statement, e.schemaStore)
	if err != nil {
		logrus.WithError(err).Errorln("Can't extract columns from SELECT statement")
		return nil, err
	}
	querySelectSettings := make([]*encryptor.QueryDataItem, 0, len(columns))
	for _, data := range columns {
		if data != nil {
			if schema := e.schemaStore.GetTableSchema(data.Table); schema != nil {
				var setting *encryptor.QueryDataItem = nil
				if data.Name == "*" {
					for _, name := range schema.Columns() {
						setting = nil
						if columnSetting := schema.GetColumnEncryptionSettings(name); columnSetting != nil {
							setting = encryptor.NewQueryDataItem(columnSetting, data.Table, name, "")
						}
						querySelectSettings = append(querySelectSettings, setting)
					}
				} else {
					if columnSetting := schema.GetColumnEncryptionSettings(data.Name); columnSetting != nil {
						setting = encryptor.NewQueryDataItem(columnSetting, data.Table, data.Name, data.Alias)
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
