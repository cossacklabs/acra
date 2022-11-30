package pseudonymization

import (
	"context"

	"github.com/cossacklabs/acra/decryptor/base"
	queryEncryptor "github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/sirupsen/logrus"
)

// TokenizeQuery replace tokenized data inside AcraStruct/AcraBlocks and change WHERE conditions to support searchable tokenization
type TokenizeQuery struct {
	coder                 queryEncryptor.DBDataCoder
	tokenEncryptor        *TokenEncryptor
	searchableQueryFilter *queryEncryptor.SearchableQueryFilter
}

// NewPostgresqlTokenizeQuery return TokenizeQuery with coder for postgresql
func NewPostgresqlTokenizeQuery(schemaStore config.TableSchemaStore, tokenEncryptor *TokenEncryptor) *TokenizeQuery {
	return &TokenizeQuery{
		searchableQueryFilter: queryEncryptor.NewSearchableQueryFilter(schemaStore, queryEncryptor.QueryFilterModeConsistentTokenization),
		tokenEncryptor:        tokenEncryptor,
		coder:                 &queryEncryptor.PostgresqlDBDataCoder{},
	}
}

// NewMySQLTokenizeQuery return TokenizeQuery with coder for mysql
func NewMySQLTokenizeQuery(schemaStore config.TableSchemaStore, tokenEncryptor *TokenEncryptor) *TokenizeQuery {
	return &TokenizeQuery{
		searchableQueryFilter: queryEncryptor.NewSearchableQueryFilter(schemaStore, queryEncryptor.QueryFilterModeConsistentTokenization),
		tokenEncryptor:        tokenEncryptor,
		coder:                 &queryEncryptor.MysqlDBDataCoder{},
	}
}

// ID returns name of this QueryObserver.
func (encryptor *TokenizeQuery) ID() string {
	return "TokenizeQuery"
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
func (encryptor *TokenizeQuery) OnQuery(ctx context.Context, query base.OnQueryObject) (base.OnQueryObject, bool, error) {
	logrus.Debugln("TokenizeQuery.OnQuery")
	stmt, err := query.Statement()
	if err != nil {
		logrus.WithError(err).Debugln("Can't parse SQL statement")
		return query, false, err
	}

	// Extract the subexpressions that we are interested in for encryption.
	// The list might be empty for non-SELECT queries or for non-eligible SELECTs.
	// In that case we don't have any more work to do here.
	items := encryptor.searchableQueryFilter.FilterSearchableComparisons(stmt)
	if len(items) == 0 {
		return query, false, nil
	}
	clientSession := base.ClientSessionFromContext(ctx)
	bindSettings := queryEncryptor.PlaceholderSettingsFromClientSession(clientSession)
	for _, item := range items {
		rightVal, ok := item.Expr.Right.(*sqlparser.SQLVal)
		if !ok {
			logrus.Debugln("expect SQLVal as Right expression for searchable consistent tokenization")
			continue
		}

		encryptor.searchableQueryFilter.ChangeSearchableOperator(item.Expr)

		err = queryEncryptor.UpdateExpressionValue(ctx, item.Expr.Right, encryptor.coder, encryptor.getTokenizerDataWithSetting(item.Setting))
		if err != nil {
			logrus.WithError(err).Debugln("Failed to update expression")
			return query, false, err
		}

		placeholderIndex, err := queryEncryptor.ParsePlaceholderIndex(rightVal)
		if err == queryEncryptor.ErrInvalidPlaceholder {
			continue
		} else if err != nil {
			return query, false, err
		}
		bindSettings[placeholderIndex] = item.Setting
	}
	logrus.Debugln("TokenizeQuery.OnQuery changed query")
	return base.NewOnQueryObjectFromStatement(stmt, nil), true, nil
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
func (encryptor *TokenizeQuery) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("TokenizeQuery.OnBind")
	// Extract the subexpressions that we are interested in for searchable encryption.
	// The list might be empty for non-SELECT queries or for non-eligible SELECTs.
	// In that case we don't have any more work to do here.
	items := encryptor.searchableQueryFilter.FilterSearchableComparisons(statement)
	if len(items) == 0 {
		return values, false, nil
	}
	// Now that we have expressions, analyze them to look for involved placeholders
	// and map them onto values that we need to update.
	indexes := make([]int, 0, len(values))
	for _, item := range items {
		switch value := item.Expr.Right.(type) {
		case *sqlparser.SQLVal:
			var err error
			index, err := queryEncryptor.ParsePlaceholderIndex(value)
			if err != nil {
				return values, false, err
			}
			if index >= len(values) {
				logrus.WithFields(logrus.Fields{"placeholder": value.Val, "index": index, "values": len(values)}).
					Warning("Invalid placeholder index")
				return values, false, queryEncryptor.ErrInvalidPlaceholder
			}
			indexes = append(indexes, index)
		}
	}
	// Finally, once we know which values to replace with tokenized values, do this replacement.
	return encryptor.replaceValuesWithTokenizedData(ctx, values, indexes)
}

func (encryptor *TokenizeQuery) replaceValuesWithTokenizedData(ctx context.Context, values []base.BoundValue, placeholders []int) ([]base.BoundValue, bool, error) {
	// If there are no interesting placholder positions then we don't have to process anything.
	if len(placeholders) == 0 {
		return values, false, nil
	}
	// Otherwise, decrypt values at positions indicated by placeholders and replace them with their HMACs.
	newValues := make([]base.BoundValue, len(values))
	copy(newValues, values)
	clientSession := base.ClientSessionFromContext(ctx)
	bindData := queryEncryptor.PlaceholderSettingsFromClientSession(clientSession)

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

func (encryptor *TokenizeQuery) getTokenizerDataWithSetting(setting config.ColumnEncryptionSetting) func(ctx context.Context, dataToTokenize []byte) (tokenized []byte, err error) {
	return func(ctx context.Context, dataToTokenize []byte) (tokenized []byte, err error) {
		logger := logrus.WithFields(logrus.Fields{"column": setting.ColumnName()})
		logger.Debugln("Searchable TokenizeQuery")

		accessContext := base.AccessContextFromContext(ctx)

		if accessContext.IsWithZone() {
			tokenized, err = encryptor.tokenEncryptor.EncryptWithZoneID(accessContext.GetZoneID(), dataToTokenize, setting)
		} else {
			clientID := setting.ClientID()
			if len(clientID) > 0 {
				logger.WithField("client_id", string(clientID)).Debugln("Tokenize with specific ClientID for column")
			} else {
				logger.WithField("client_id", string(accessContext.GetClientID())).Debugln("Tokenize with ClientID from connection")
				clientID = accessContext.GetClientID()
			}
			tokenized, err = encryptor.tokenEncryptor.EncryptWithClientID(clientID, dataToTokenize, setting)
		}

		return
	}
}
