package postgresql

import (
	"context"
	"errors"
	"strconv"

	pg_query "github.com/Zhaars/pg_query_go/v4"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	queryEncryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
)

// ErrStatementAlreadyInRegistry represent an error that prepared statement already exist in session registry
var (
	ErrStatementAlreadyInRegistry    = errors.New("prepared statement already store in registry")
	ErrStatementNotPresentInRegistry = errors.New("prepared statement not present in registry")
)

// PreparedStatementsQuery QueryDataEncryptor process PostgreSQL SQL PreparedStatement
type PreparedStatementsQuery struct {
	session       base.ClientSession
	queryObserver base.QueryObserver
	parser        *sqlparser.Parser
	coder         queryEncryptor.DBDataCoder
}

// NewPostgresqlPreparedStatementsQuery create new QueryDataEncryptor to handle SQL PreparedStatement in the following format
// `prepare {prepare_statement_name} (params...) as the sql-query` and `execute  (values...) {prepare_statement_name}`
func NewPostgresqlPreparedStatementsQuery(session base.ClientSession, parser *sqlparser.Parser, queryObserver base.QueryObserver) *PreparedStatementsQuery {
	return &PreparedStatementsQuery{parser: parser, session: session, queryObserver: queryObserver, coder: &postgresql.DBDataCoder{}}
}

// ID returns name of this QueryObserver.
func (encryptor *PreparedStatementsQuery) ID() string {
	return "PreparedStatementsQuery"
}

// OnQuery processes query text before database sees it.
func (encryptor *PreparedStatementsQuery) OnQuery(ctx context.Context, query base.OnQueryObject) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnQuery")
	parseResult, err := query.PgStatement()
	if err != nil {
		logrus.WithError(err).Debugln("Can't parse SQL statement")
		return query, false, nil
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

func (encryptor *PreparedStatementsQuery) onPrepare(ctx context.Context, parseResult *pg_query.ParseResult) (base.OnQueryObject, bool, error) {
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
	stmtText, err := pg_query.Deparse(&pg_query.ParseResult{
		Stmts: []*pg_query.RawStmt{{
			Stmt: stmt,
		}},
	})
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to deparse in Prepare statement")
		return nil, false, err
	}

	var preparedStatement = NewPreparedStatement(preparedStatementName, stmtText, stmt)

	if err := registry.AddStatement(preparedStatement); err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to add prepared statement")
		return nil, false, err
	}

	// run OnQuery with inner query of prepared statement
	changedObject, changed, err := encryptor.queryObserver.OnQuery(ctx, base.NewOnQueryObjectFromQuery(stmtText, encryptor.parser))
	if err != nil {
		return nil, false, err
	}

	// if the inner query of prepared statement was changed, replace it in sqlparser.PreparedQuery
	if changed {
		changedStatement, err := changedObject.PgStatement()
		if err != nil {
			return nil, false, err
		}
		prepareQuery.Query = changedStatement.Stmts[0].Stmt
	}

	changedQuery, err := pg_query.Deparse(parseResult)
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to deparse result Prepare query")
		return nil, false, err
	}

	logrus.WithField("prepared_name", preparedStatementName).Debug("Registered new prepared statement")
	return base.NewOnQueryObjectFromQuery(changedQuery, encryptor.parser), changed, nil
}

func (encryptor *PreparedStatementsQuery) onExecute(ctx context.Context, parseResult *pg_query.ParseResult) (base.OnQueryObject, bool, error) {
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

	// TODO: fixed once adjusted the interfaces
	stmt, err := encryptor.parser.Parse(preparedStatement.QueryText())
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed tp parse prepared statement")
		return nil, false, err
	}

	newValues, changed, err := encryptor.queryObserver.OnBind(ctx, stmt, values)
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

			// TODO: after encryption its possible we need to change a AConst
			switch {
			case param.GetAConst().GetSval() != nil:
				param.GetAConst().GetSval().Sval = string(newValueData)
			case param.GetAConst().GetIval() != nil:
				iVal, err := strconv.Atoi(string(newValueData))
				if err != nil {
					return nil, false, err
				}
				param.GetAConst().GetIval().Ival = int32(iVal)
			case param.GetAConst().GetFval() != nil:
				param.GetAConst().GetFval().Fval = string(newValueData)
			}
		}
	}

	changedQuery, err := pg_query.Deparse(parseResult)
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to deparse result Prepare query")
		return nil, false, err
	}

	return base.NewOnQueryObjectFromQuery(changedQuery, encryptor.parser), true, nil
}

func (encryptor *PreparedStatementsQuery) onDeallocate(ctx context.Context, parseResult *pg_query.ParseResult) (base.OnQueryObject, bool, error) {
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
func (encryptor *PreparedStatementsQuery) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnBind")
	return values, false, nil
}
