package postgresql

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	"github.com/cossacklabs/acra/logging"
)

// ErrStatementAlreadyInRegistry represent an error that prepared statement already exist in session registry
var (
	ErrStatementAlreadyInRegistry    = errors.New("prepared statement already store in registry")
	ErrStatementNotPresentInRegistry = errors.New("prepared statement not present in registry")
)

// PreparedStatementsQuery QueryDataEncryptor process PostgreSQL SQL PreparedStatement
type PreparedStatementsQuery struct {
	session       base.ClientSession
	queryObserver postgresql.QueryObserver
}

// NewPostgresqlPreparedStatementsQuery create new QueryDataEncryptor to handle SQL PreparedStatement in the following format
// `prepare {prepare_statement_name} (params...) as the sql-query` and `execute  (values...) {prepare_statement_name}`
func NewPostgresqlPreparedStatementsQuery(session base.ClientSession, queryObserver postgresql.QueryObserver) *PreparedStatementsQuery {
	return &PreparedStatementsQuery{session: session, queryObserver: queryObserver}
}

// ID returns name of this QueryObserver.
func (encryptor *PreparedStatementsQuery) ID() string {
	return "PreparedStatementsQuery"
}

// OnQuery processes query text before database sees it.
func (encryptor *PreparedStatementsQuery) OnQuery(ctx context.Context, query postgresql.OnQueryObject) (postgresql.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnQuery")
	parseResult, err := query.Statement()
	if err != nil {
		logrus.WithError(err).Debugln("Can't parse SQL statement")
		return query, false, nil
	}

	if len(parseResult.Stmts) == 0 {
		return nil, false, err
	}

	switch {
	case parseResult.Stmts[0].Stmt.GetPrepareStmt() != nil:
		return encryptor.onPrepare(ctx, parseResult)
	case parseResult.Stmts[0].Stmt.GetExecuteStmt() != nil:
		return encryptor.onExecute(ctx, parseResult)
	case parseResult.Stmts[0].Stmt.GetDeallocateStmt() != nil:
		return encryptor.onDeallocate(ctx, parseResult)
	default:
		return query, false, nil
	}
}

func (encryptor *PreparedStatementsQuery) onPrepare(ctx context.Context, parseResult *pg_query.ParseResult) (postgresql.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Prepare")

	var prepareQuery = parseResult.Stmts[0].Stmt.GetPrepareStmt()
	var preparedStatementName = prepareQuery.GetName()
	var registry = encryptor.session.PreparedStatementRegistry()

	// PostgreSQL allows create statement only once during the session
	if _, err := registry.StatementByName(preparedStatementName); err == nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement already stored in registry")
		return nil, false, ErrStatementAlreadyInRegistry
	}

	var stmt = prepareQuery.GetQuery()
	var prepareParseResult = &pg_query.ParseResult{
		Stmts: []*pg_query.RawStmt{{
			Stmt: stmt,
		}},
	}
	stmtText, err := pg_query.Deparse(prepareParseResult)
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to deparse in Prepare statement")
		return nil, false, err
	}

	var preparedStatement = NewPreparedStatement(preparedStatementName, stmtText, prepareParseResult)

	if err := registry.AddStatement(preparedStatement); err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to add prepared statement")
		return nil, false, err
	}

	// run OnQuery with inner query of prepared statement
	changedObject, changed, err := encryptor.queryObserver.OnQuery(ctx, postgresql.NewOnQueryObjectFromStatement(prepareParseResult))
	if err != nil {
		return nil, false, err
	}

	// if the inner query of prepared statement was changed, replace it in sqlparser.PreparedQuery
	if changed {
		changedStatement, err := changedObject.Statement()
		if err != nil {
			return nil, false, err
		}
		prepareQuery.Query = changedStatement.Stmts[0].Stmt
	}

	logrus.WithField("prepared_name", preparedStatementName).Debug("Registered new prepared statement")
	return postgresql.NewOnQueryObjectFromStatement(parseResult), changed, nil
}

func (encryptor *PreparedStatementsQuery) onExecute(ctx context.Context, parseResult *pg_query.ParseResult) (postgresql.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Execute")

	var executeQuery = parseResult.Stmts[0].Stmt.GetExecuteStmt()
	var preparedStatementName = executeQuery.GetName()
	var registry = encryptor.session.PreparedStatementRegistry()

	preparedStatement, err := registry.StatementByName(preparedStatementName)
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement not present in registry")
		return nil, false, ErrStatementNotPresentInRegistry
	}

	// collect all BoundValues
	values := make([]base.BoundValue, 0, len(executeQuery.GetParams()))
	for _, param := range executeQuery.GetParams() {
		if param.GetAConst() == nil {
			continue
		}

		switch {
		case param.GetAConst().GetSval() != nil:
			values = append(values, NewPgBoundValue([]byte(param.GetAConst().GetSval().GetSval()), bindFormatText))
		case param.GetAConst().GetIval() != nil:
			val := param.GetAConst().GetIval().GetIval()
			values = append(values, NewPgBoundValue([]byte(strconv.Itoa(int(val))), bindFormatText))
		case param.GetAConst().GetFval() != nil:
			values = append(values, NewPgBoundValue([]byte(param.GetAConst().GetFval().GetFval()), bindFormatText))
		case param.GetAConst().GetIsnull():
			values = append(values, NewPgBoundValue(nil, bindFormatText))
		default:
			logrus.WithError(err).Debugln("Unexpected Execute query Values format")
		}
	}

	newValues, changed, err := encryptor.queryObserver.OnBind(ctx, preparedStatement.Query(), values)
	if err != nil {
		return nil, false, err
	}

	if changed {
		for i, param := range executeQuery.GetParams() {
			if param.GetAConst().GetIsnull() {
				continue
			}

			newValueData, err := newValues[i].GetData(nil)
			if err != nil {
				return nil, false, err
			}

			// TODO: potentially we can move this logic to encoder
			switch {
			case param.GetAConst().GetSval() != nil:
				param.GetAConst().GetSval().Sval = string(newValueData)
			case param.GetAConst().GetIval() != nil:
				if iVal, err := strconv.ParseInt(string(newValueData), 10, 32); err == nil {
					param.GetAConst().GetIval().Ival = int32(iVal)
					continue
				}

				fmt.Println("-----------------------------------========================================")
				// during tokenization data can come as int32 but with token_type: int64 and after tokenization we should switch the AConst type
				if _, err := strconv.ParseInt(string(newValueData), 10, 64); err == nil {
					*param.GetAConst() = pg_query.A_Const{
						Val: &pg_query.A_Const_Fval{
							Fval: &pg_query.Float{
								Fval: string(newValueData),
							},
						},
					}
				}
			case param.GetAConst().GetFval() != nil:
				param.GetAConst().GetFval().Fval = string(newValueData)
			}
		}
	}

	fmt.Println(postgresql.NewOnQueryObjectFromStatement(parseResult).Query())
	return postgresql.NewOnQueryObjectFromStatement(parseResult), true, nil
}

func (encryptor *PreparedStatementsQuery) onDeallocate(ctx context.Context, parseResult *pg_query.ParseResult) (postgresql.OnQueryObject, bool, error) {
	var registry = encryptor.session.PreparedStatementRegistry()
	var preparedStatementName = parseResult.Stmts[0].Stmt.GetDeallocateStmt().GetName()

	if _, err := registry.StatementByName(preparedStatementName); err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement not present in registry")
		return nil, false, ErrStatementNotPresentInRegistry
	}

	return nil, false, registry.DeleteStatement(preparedStatementName)
}

// OnBind just a stub method of QueryObserver of  PreparedStatementsQuery
func (encryptor *PreparedStatementsQuery) OnBind(ctx context.Context, statement *pg_query.ParseResult, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnBind")
	return values, false, nil
}
