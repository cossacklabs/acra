package postgresql

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	queryEncryptor "github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/sqlparser"
)

// PreparedStatementsQuery calculate hmac for data inside AcraStruct and change WHERE conditions to support searchable encryption
type PreparedStatementsQuery struct {
	session       base.ClientSession
	queryObserver base.QueryObserver
	parser        *sqlparser.Parser
	coder         queryEncryptor.DBDataCoder
}

// NewPostgresqlPreparedStatementsQuery create QueryDataEncryptor with PostgresqlDBDataCoder
func NewPostgresqlPreparedStatementsQuery(session base.ClientSession, parser *sqlparser.Parser, queryObserver base.QueryObserver) *PreparedStatementsQuery {
	return &PreparedStatementsQuery{parser: parser, session: session, queryObserver: queryObserver, coder: &queryEncryptor.PostgresqlDBDataCoder{}}
}

// ID returns name of this QueryObserver.
func (encryptor *PreparedStatementsQuery) ID() string {
	return "PreparedStatementsQuery"
}

// OnQuery processes query text before database sees it.
func (encryptor *PreparedStatementsQuery) OnQuery(ctx context.Context, query base.OnQueryObject) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnQuery")
	parsedQuery, err := encryptor.parser.Parse(query.Query())
	if err != nil {
		logrus.WithError(err).Debugln("Can't parse SQL statement")
		return query, false, nil
	}

	switch processQuery := parsedQuery.(type) {
	case *sqlparser.Prepare:
		return encryptor.onPrepare(ctx, processQuery)
	case *sqlparser.Execute:
		return encryptor.onExecute(ctx, processQuery)
	case *sqlparser.DeallocatePrepare:
		//TODO: implement onDeallocate
	default:
		return query, false, nil
	}
	return query, false, nil
}

func (encryptor *PreparedStatementsQuery) onPrepare(ctx context.Context, prepareQuery *sqlparser.Prepare) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Prepare")

	var preparedStatementName = prepareQuery.PreparedStatementName.String()
	var registry = encryptor.session.PreparedStatementRegistry()

	// PostgreSQL allows create statement only once during the session
	if _, err := registry.StatementByName(prepareQuery.PreparedStatementName.String()); err == nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement already present in registry")
		return nil, false, errors.New("")
	}

	var stmt = prepareQuery.PreparedStatementQuery.(sqlparser.Statement)
	var preparedStatement = NewPreparedStatement(preparedStatementName, sqlparser.String(stmt), stmt)

	if err := registry.AddStatement(preparedStatement); err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to add prepared statement")
		return nil, false, err
	}

	changedObject, changed, err := encryptor.queryObserver.OnQuery(ctx, base.NewOnQueryObjectFromStatement(stmt, encryptor.parser))
	if err != nil {
		return nil, false, err
	}

	if changed {
		changedStatement, err := changedObject.Statement()
		if err != nil {
			return nil, false, err
		}

		switch castedStmt := changedStatement.(type) {
		case *sqlparser.Insert:
			prepareQuery.PreparedStatementQuery = castedStmt
		case *sqlparser.Select:
			prepareQuery.PreparedStatementQuery = castedStmt
		case *sqlparser.Update:
			prepareQuery.PreparedStatementQuery = castedStmt
		case *sqlparser.Delete:
			prepareQuery.PreparedStatementQuery = castedStmt
		}
	}

	logrus.WithField("prepared_name", preparedStatementName).Debug("Registered new prepared statement")
	return base.NewOnQueryObjectFromStatement(prepareQuery, encryptor.parser), changed, nil
}

func (encryptor *PreparedStatementsQuery) onExecute(ctx context.Context, executeQuery *sqlparser.Execute) (base.OnQueryObject, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Execute")

	var preparedStatementName = executeQuery.PreparedStatementName.String()
	var registry = encryptor.session.PreparedStatementRegistry()

	preparedStatement, err := registry.StatementByName(preparedStatementName)
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("PreparedStatement already present in registry")
		return nil, false, err
	}

	values := make([]base.BoundValue, 0, len(executeQuery.Values))
	for _, value := range executeQuery.Values {
		switch val := value.(type) {
		case *sqlparser.SQLVal:
			values = append(values, NewPgBoundValue(val.Val, bindFormatText))
		case *sqlparser.NullVal:
			values = append(values, NewPgBoundValue(nil, bindFormatText))
		}
	}

	stmt, err := encryptor.parser.Parse(preparedStatement.QueryText())
	if err != nil {
		logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorGeneral).
			WithError(err).Errorln("Failed to parse prepared statement from registry")
		return nil, false, err
	}

	newValues, changed, err := encryptor.queryObserver.OnBind(ctx, stmt, values)
	if err != nil {
		return nil, false, err
	}

	if changed {
		for i, value := range executeQuery.Values {
			sqlVal, ok := value.(*sqlparser.SQLVal)
			if ok {
				newValueData, err := newValues[i].GetData(nil)
				if err != nil {
					return nil, false, err
				}

				sqlVal.Val = newValueData
			}
		}
	}

	return base.NewOnQueryObjectFromStatement(executeQuery, encryptor.parser), true, nil
}

func (encryptor *PreparedStatementsQuery) onDeallocate(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.Deallocate")
	return nil, false, nil
}

func (encryptor *PreparedStatementsQuery) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("PreparedStatementsQuery.OnBind")
	return nil, false, nil
}
