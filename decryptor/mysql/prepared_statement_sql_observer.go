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
	encryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/mysql"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
)

// ErrStatementNotPresentInRegistry represent an error that prepared statement already exist in session registry
var ErrStatementNotPresentInRegistry = errors.New("prepared statement not present in registry")

// PreparedStatementsQuery process MySQL SQL PreparedStatement
type PreparedStatementsQuery struct {
	proxyHandler        *Handler
	parser              *sqlparser.Parser
	encryptor           encryptor.DataEncryptor
	schemaStore         config.TableSchemaStore
	coder               encryptor.DBDataCoder
	querySelectSettings []*encryptor.QueryDataItem
}

// NewMySQLPreparedStatementsQuery create new PreparedStatementsQuery to handle SQL PreparedStatement in the following format
// https://dev.mysql.com/doc/refman/8.0/en/sql-prepared-statements.html
func NewMySQLPreparedStatementsQuery(proxyHandler *Handler, parser *sqlparser.Parser, schemaStore config.TableSchemaStore) *PreparedStatementsQuery {
	return &PreparedStatementsQuery{
		proxyHandler,
		parser,
		nil,
		schemaStore,
		&mysql.MysqlDBDataCoder{},
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
	if ok && e.querySelectSettings != nil {
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
	var preparedStatementName = prepareQuery.PreparedStatementName.ValueForConfig()

	// MySQL allows create statements many time, so just log in case of already registered
	_, err := e.proxyHandler.registry.StatementByID(preparedStatementName)
	if err == nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement already stored in registry")
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
			setArgPreparedStatement := setArgStmt.Statement()

			// add new PreparedStatement using different name
			// 1. SET @s = 'SELECT SQRT(POW(?,2) + POW(?,2)) AS hypotenuse';
			//    - store in registry with name @s
			// 2. On PREPARE stmt2 FROM @s;
			//    - reset with name stmt2 to use in execute statement
			// 3. On EXECUTE stmt2 USING @a, @b;
			//    - read by stmt2 name
			var preparedStatement = NewPreparedStatementWithName(preparedStatementName, setArgPreparedStatement.QueryText(), setArgPreparedStatement.Query())
			var preparedStatementItem = NewPreparedStatementItem(preparedStatement, setArgStmt.QuerySettings())
			e.proxyHandler.registry.AddStatement(preparedStatementItem)
		} else {
			logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				Errorln("Error to cast PreparedStatementQuery to sqlparser.Statement")
		}
		return nil, false, nil
	}

	changedObject, changed, err := e.onQuery(ctx, preparedStatementName, base.NewOnQueryObjectFromStatement(stmt, e.parser))
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
		argName := arg.Name.ValueForConfig()

		ok, err := e.handleQueryFromSetArg(ctx, sqlVal, argName)
		if ok {
			logrus.Debugln("New PreparedStatement from Set Arg")
			changedRes = true
			continue
		}

		encryptedData, err := e.handleColumnFromSetArg(ctx, sqlVal, argName)
		if err != nil {
			logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
				WithError(err).Errorln("Failed to handle column from Set arg")
			return nil, false, err
		}

		if encryptedData != nil && !bytes.Equal(encryptedData, sqlVal.Val) {
			output := make([]byte, hex.EncodedLen(len(encryptedData)))
			hex.Encode(output, encryptedData)

			sqlVal.Val = output
			sqlVal.Type = sqlparser.HexVal
			changedRes = true
		}
	}

	return base.NewOnQueryObjectFromStatement(setQuery, e.parser), changedRes, nil
}

func (e *PreparedStatementsQuery) handleColumnFromSetArg(ctx context.Context, sqlVal *sqlparser.SQLVal, argName string) ([]byte, error) {
	// MySQL set arg query format:
	// SET @a = 3;
	// Acra expect arguments in the following format: {table_from_encryptor_config}{delimiter}{column_from_encryptor_config}, e.g
	// users__name - where `__` is the default delimiter could be overwritten
	var delim = e.schemaStore.GetDatabaseSettings().GetMySQLDatabaseSettings().GetPreparedStatementsSetArgDelimiter()

	splits := strings.Split(argName, delim)
	if len(splits) != 2 {
		logrus.WithField("argument", argName).Debugln("unexpected Set arg name for processing")
		return nil, nil
	}

	var columnName = splits[1]
	var tableName = strings.TrimPrefix(splits[0], "@")

	schema := e.schemaStore.GetTableSchema(tableName)
	if schema == nil {
		logrus.Debugf("Hasn't schema for table in SET query %s", tableName)
		return nil, nil
	}

	columnSetting := schema.GetColumnEncryptionSettings(columnName)
	if columnSetting == nil {
		logrus.Debugf("No column encryption setting %s", columnName)
		return nil, nil
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
		return nil, err
	}

	encryptedData, err := e.encryptor.EncryptWithClientID(clientID, rawData, columnSetting)
	if err != nil {
		return nil, err
	}
	return encryptedData, nil
}

func (e *PreparedStatementsQuery) handleQueryFromSetArg(ctx context.Context, sqlVal *sqlparser.SQLVal, argName string) (bool, error) {
	// Prepared statement could be supply the text of the statement as a user variable:
	// SET @s = 'SELECT SQRT(POW(?,2) + POW(?,2)) AS hypotenuse';
	// PREPARE stmt2 FROM @s;
	// https://dev.mysql.com/doc/refman/8.0/en/sql-prepared-statements.html
	//TODO: potentially we can get it from sqlparser directly
	prepareQuery, err := sqlparser.NewPreparedQueryFromString(string(sqlVal.Val))
	if err != nil || prepareQuery == nil {
		return false, nil
	}

	queryObj := base.NewOnQueryObjectFromStatement(prepareQuery.(sqlparser.Statement), e.parser)
	changedObject, changed, err := e.onQuery(ctx, argName, queryObj)
	if err != nil {
		return false, err
	}

	if changed {
		if err := e.updateChangedQuery(changedObject); err != nil {
			return false, err
		}

		sqlVal.Val = []byte(changedObject.Query())
	}
	return changed, nil
}

func (e *PreparedStatementsQuery) onExecute(ctx context.Context, executeQuery *sqlparser.Execute) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Execute")
	var preparedStatementName = executeQuery.PreparedStatementName.ValueForConfig()

	stmtItem, err := e.proxyHandler.registry.StatementByID(preparedStatementName)
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement not present in registry")
		return nil, false, ErrStatementNotPresentInRegistry
	}

	logrus.Debugln("Set query settings from registry")
	e.querySelectSettings = stmtItem.QuerySettings()

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

	e.querySelectSettings = nil
	e.proxyHandler.registry.DeleteStatementByID(preparedStatementName)
	return nil, false, nil
}

func (e *PreparedStatementsQuery) onQuery(ctx context.Context, preparedStatementName string, queryObj base.OnQueryObject) (base.OnQueryObject, bool, error) {
	stmt, err := queryObj.Statement()
	if err != nil {
		return nil, false, err
	}

	var query = queryObj.Query()
	var preparedStatement = NewPreparedStatementWithName(preparedStatementName, query, stmt)

	changedObject, changed, err := e.proxyHandler.queryObserverManager.OnQuery(ctx, queryObj)
	if err != nil {
		logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).Errorln("Error occurred in OnQuery handler")
		return nil, false, err
	}

	var querySetting []*encryptor.QueryDataItem
	switch query := stmt.(type) {
	case *sqlparser.Select:
		querySetting, err = encryptor.ParseQuerySettings(ctx, query, e.schemaStore)
		if err != nil {
			logrus.WithError(err).WithField(logging.FieldKeyEventCode, logging.EventCodeErrorEncryptQueryData).Errorln("Failed to parse querySettings for select in Prepare")
			return nil, false, err
		}
	}

	e.proxyHandler.registry.AddStatement(NewPreparedStatementItem(preparedStatement, querySetting))
	return changedObject, changed, nil
}

// OnBind just a stub method of QueryObserver of  PreparedStatementsQuery
func (e *PreparedStatementsQuery) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnBind")
	return values, false, nil
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

		if rVal, ok := item.Expr.Right.(*sqlparser.SQLVal); ok && bytes.HasPrefix(rVal.Val, []byte(":v")) {
			logrus.Debugln("OnPrepare: replace placeholder with substr for search")
			item.Expr.Right = &sqlparser.SubstrExpr{
				Name: &sqlparser.ColName{
					Name: sqlparser.NewColIdentUnquote("?"),
				},
				From: sqlparser.NewIntVal([]byte{'1'}),
				To:   sqlparser.NewIntVal(hashSize),
			}
		}
	}

	return nil
}

func (e *PreparedStatementsQuery) filterSearchableComparisons(statement sqlparser.Statement) []encryptor.SearchableExprItem {
	tableExps, err := encryptor.FilterTableExpressions(statement)
	if err != nil {
		logrus.Debugln("Unsupported search query")
		return nil
	}

	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := encryptor.GetWhereStatements(statement)
	if err != nil {
		logrus.WithError(err).Debugln("Failed to extract WHERE clauses")
		return nil
	}

	var searchableExprs []encryptor.SearchableExprItem
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

// filterColumnEqualComparisonExprs return only <ColName> = <VALUE> or <ColName> != <VALUE> or <ColName> <=> <VALUE> expressions
func (e *PreparedStatementsQuery) filterColumnEqualComparisonExprs(stmt sqlparser.SQLNode, tableExpr sqlparser.TableExprs) ([]encryptor.SearchableExprItem, error) {
	var exprs []encryptor.SearchableExprItem

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

		lColumnSetting := encryptor.GetColumnSetting(lColumn.Name, columnInfo.Table, e.schemaStore)
		if lColumnSetting == nil {
			return true, nil
		}

		if !lColumnSetting.IsSearchable() {
			return true, nil
		}

		exprs = append(exprs, encryptor.SearchableExprItem{
			Expr:    comparisonExpr,
			Setting: lColumnSetting,
		})
		return true, nil
	}, stmt)
	return exprs, err
}
