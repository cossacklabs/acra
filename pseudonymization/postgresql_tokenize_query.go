package pseudonymization

import (
	"context"

	pg_query "github.com/cossacklabs/pg_query_go/v5"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	encryptor_base "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/postgresql"
)

// PostgreSQLTokenizeQuery replace tokenized data inside AcraStruct/AcraBlocks and change WHERE conditions to support searchable tokenization
type PostgreSQLTokenizeQuery struct {
	coder                 *postgresql.PgQueryDBDataCoder
	tokenEncryptor        *TokenEncryptor
	searchableQueryFilter *postgresql.SearchableQueryFilter
	schemaStore           config.TableSchemaStore
}

// NewPostgresqlTokenizeQuery return PostgreSQLTokenizeQuery with coder for postgresql
func NewPostgresqlTokenizeQuery(schemaStore config.TableSchemaStore, tokenEncryptor *TokenEncryptor) *PostgreSQLTokenizeQuery {
	return &PostgreSQLTokenizeQuery{
		searchableQueryFilter: postgresql.NewSearchableQueryFilter(schemaStore, encryptor_base.QueryFilterModeConsistentTokenization),
		tokenEncryptor:        tokenEncryptor,
		coder:                 &postgresql.PgQueryDBDataCoder{},
		schemaStore:           schemaStore,
	}
}

// ID returns name of this QueryObserver.
func (encryptor *PostgreSQLTokenizeQuery) ID() string {
	return "PostgreSQLTokenizeQuery"
}

// OnQuery processes query text before database sees it.
//
// Tokenized searchable encryption rewrites WHERE clauses with equality comparisons like this:
//
//	WHERE column = 'value'   ===>   WHERE column = tokenize('value')
//
// If the query is a parameterized prepared query then OnQuery() rewriting yields this:
//
//	WHERE column = $1        ===>   WHERE column = tokenize($1)
//
// and actual "value" is passed via parameters later. See OnBind() for details.
func (encryptor *PostgreSQLTokenizeQuery) OnQuery(ctx context.Context, query postgresql.OnQueryObject) (postgresql.OnQueryObject, bool, error) {
	logrus.Debugln("PostgreSQLTokenizeQuery.OnQuery")

	parseResult, err := query.Statement()
	if err != nil || len(parseResult.Stmts) == 0 {
		logrus.Debugln("Failed to parse incoming query", err)
		return query, false, nil
	}

	// Extract the subexpressions that we are interested in for encryption.
	// The list might be empty for non-SELECT queries or for non-eligible SELECTs.
	// In that case we don't have any more work to do here.
	items := encryptor.searchableQueryFilter.FilterSearchableComparisons(parseResult)
	if len(items) == 0 {
		return query, false, nil
	}

	clientSession := base.ClientSessionFromContext(ctx)
	bindSettings := encryptor_base.PlaceholderSettingsFromClientSession(clientSession)
	for _, item := range items {
		if !item.Setting.IsTokenized() {
			continue
		}

		rExpr := item.Expr.Rexpr.GetAConst()
		if typeCast := item.Expr.Rexpr.GetTypeCast(); typeCast != nil {
			rExpr = typeCast.GetArg().GetAConst()
		}

		if rExpr == nil {
			logrus.Debugln("expect SQLVal as Right expression for searchable consistent tokenization")
			continue
		}

		encryptor.searchableQueryFilter.ChangeSearchableOperator(item.Expr)

		err = postgresql.UpdateExpressionValue(ctx, rExpr, encryptor.coder, item.Setting, encryptor.getTokenizerDataWithSetting(item.Setting))
		if err != nil {
			logrus.WithError(err).Debugln("Failed to update expression")
			return query, false, err
		}

		paramRef := item.Expr.Rexpr.GetParamRef()
		if paramRef == nil {
			continue
		}
		placeholderIndex := paramRef.GetNumber() - 1
		bindSettings[int(placeholderIndex)] = item.Setting
	}

	logrus.Debugln("PostgreSQLTokenizeQuery.OnQuery changed query")
	return postgresql.NewOnQueryObjectFromStatement(parseResult), true, nil
}

// OnBind processes bound values for prepared statements.
//
// Searchable tokenization rewrites WHERE clauses with equality comparisons like this:
//
//	WHERE column = 'value'   ===>   WHERE column = tokenize('value')
//
// If the query is a parameterized prepared query then OnQuery() rewriting yields this:
//
//	WHERE column = $1        ===>   WHERE column = tokenize($1)
//
// and actual "value" is passed via parameters, visible here in OnBind().
func (encryptor *PostgreSQLTokenizeQuery) OnBind(ctx context.Context, parseResult *pg_query.ParseResult, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("PostgreSQLTokenizeQuery.OnBind")

	// Extract the subexpressions that we are interested in for searchable encryption.
	// The list might be empty for non-SELECT queries or for non-eligible SELECTs.
	// In that case we don't have any more work to do here.
	items := encryptor.searchableQueryFilter.FilterSearchableComparisons(parseResult)
	if len(items) == 0 {
		return values, false, nil
	}
	// Now that we have expressions, analyze them to look for involved placeholders
	// and map them onto values that we need to update.
	indexes := make([]int, 0, len(values))
	for _, item := range items {
		if !item.Setting.IsTokenized() {
			continue
		}

		paramRef := item.Expr.Rexpr.GetParamRef()
		if paramRef == nil {
			continue
		}
		index := int(paramRef.GetNumber() - 1)
		if index >= len(values) {
			logrus.WithFields(logrus.Fields{"placeholder": paramRef.GetNumber(), "index": index, "values": len(values)}).
				Warning("Invalid placeholder index")
			return values, false, encryptor_base.ErrInvalidPlaceholder
		}
		indexes = append(indexes, index)
	}

	bindData := postgresql.ParseSearchQueryPlaceholdersSettings(parseResult, encryptor.schemaStore)
	if len(bindData) > len(indexes) {
		return values, false, nil
	}
	// Finally, once we know which values to replace with tokenized values, do this replacement.
	return encryptor.replaceValuesWithTokenizedData(ctx, values, indexes, bindData)
}

func (encryptor *PostgreSQLTokenizeQuery) replaceValuesWithTokenizedData(ctx context.Context, values []base.BoundValue, placeholders []int, bindData map[int]config.ColumnEncryptionSetting) ([]base.BoundValue, bool, error) {
	// If there are no interesting placholder positions then we don't have to process anything.
	if len(placeholders) == 0 {
		return values, false, nil
	}
	// Otherwise, decrypt values at positions indicated by placeholders and replace them with their HMACs.
	newValues := make([]base.BoundValue, len(values))
	copy(newValues, values)

	for _, valueIndex := range placeholders {
		var encryptionSetting config.ColumnEncryptionSetting = nil
		if bindData != nil {
			setting, ok := bindData[valueIndex]
			if ok {
				encryptionSetting = setting
			}
		}

		if encryptionSetting == nil {
			continue
		}

		data, err := values[valueIndex].GetData(encryptionSetting)
		if err != nil {
			return values, false, err
		}

		tokenizeFunc := encryptor.getTokenizerDataWithSetting(encryptionSetting)
		tokenized, err := tokenizeFunc(ctx, data)
		if err != nil {
			logrus.WithError(err).WithField("index", valueIndex).Debug("Failed to encrypt column")
			return values, false, err
		}
		// it is ok to ignore the error if not column setting provided
		_ = newValues[valueIndex].SetData(tokenized, encryptionSetting)
	}
	return newValues, true, nil
}

func (encryptor *PostgreSQLTokenizeQuery) getTokenizerDataWithSetting(setting config.ColumnEncryptionSetting) func(ctx context.Context, dataToTokenize []byte) (tokenized []byte, err error) {
	return func(ctx context.Context, dataToTokenize []byte) (tokenized []byte, err error) {
		logger := logrus.WithFields(logrus.Fields{"column": setting.ColumnName()})
		logger.Debugln("Searchable PostgreSQLTokenizeQuery")

		accessContext := base.AccessContextFromContext(ctx)
		clientID := setting.ClientID()
		if len(clientID) > 0 {
			logger.WithField("client_id", string(clientID)).Debugln("Tokenize with specific ClientID for column")
		} else {
			logger.WithField("client_id", string(accessContext.GetClientID())).Debugln("Tokenize with ClientID from connection")
			clientID = accessContext.GetClientID()
		}
		tokenized, err = encryptor.tokenEncryptor.EncryptWithClientID(clientID, dataToTokenize, setting)
		return
	}
}
