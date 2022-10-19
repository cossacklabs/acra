/*
Copyright 2018, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package decryptor

import (
	"context"
	"fmt"

	"github.com/cossacklabs/acra/decryptor/base"
	queryEncryptor "github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
)

// HashDecryptStore that used by HashQuery
type HashDecryptStore interface {
	keystore.HmacKeyStore
	keystore.DataEncryptorKeyStore
}

// HashQuery calculate hmac for data inside AcraStruct and change WHERE conditions to support searchable encryption
type HashQuery struct {
	keystore              HashDecryptStore
	searchableQueryFilter *queryEncryptor.SearchableQueryFilter
	coder                 queryEncryptor.DBDataCoder
	decryptor             base.ExtendedDataProcessor
	parser                *sqlparser.Parser
}

// NewPostgresqlHashQuery return HashQuery with coder for postgresql
func NewPostgresqlHashQuery(keystore HashDecryptStore, schemaStore config.TableSchemaStore, processor base.ExtendedDataProcessor) *HashQuery {
	searchableQueryFilter := queryEncryptor.NewSearchableQueryFilter(schemaStore, queryEncryptor.QueryFilterModeSearchableEncryption)
	return &HashQuery{keystore: keystore, coder: &queryEncryptor.PostgresqlDBDataCoder{}, searchableQueryFilter: searchableQueryFilter, decryptor: processor}
}

// NewMysqlHashQuery return HashQuery with coder for mysql
func NewMysqlHashQuery(keystore HashDecryptStore, schemaStore config.TableSchemaStore, processor base.ExtendedDataProcessor) *HashQuery {
	searchableQueryFilter := queryEncryptor.NewSearchableQueryFilter(schemaStore, queryEncryptor.QueryFilterModeSearchableEncryption)
	return &HashQuery{keystore: keystore, coder: &queryEncryptor.MysqlDBDataCoder{}, searchableQueryFilter: searchableQueryFilter, decryptor: processor}
}

// ID returns name of this QueryObserver.
func (encryptor *HashQuery) ID() string {
	return "HashQuery"
}

// OnQuery processes query text before database sees it.
//
// Searchable encryption rewrites WHERE clauses with equality comparisons like this:
//
//	WHERE column = 'value'   ===>   WHERE substring(column, 1, <HMAC_size>) = <HMAC('value')>
//
// If the query is a parameterized prepared query then OnQuery() rewriting yields this:
//
//	WHERE column = $1        ===>   WHERE substring(column, 1, <HMAC_size>) = $1
//
// and actual "value" is passed via parameters later. See OnBind() for details.
func (encryptor *HashQuery) OnQuery(ctx context.Context, query base.OnQueryObject) (base.OnQueryObject, bool, error) {
	logrus.Debugln("HashQuery.OnQuery")
	stmt, err := query.Statement()
	if err != nil {
		logrus.WithError(err).Debugln("Can't parse SQL statement")
		return query, false, err
	}
	// Extract the subexpressions that we are interested in for searchable encryption.
	// The list might be empty for non-SELECT queries or for non-eligible SELECTs.
	// In that case we don't have any more work to do here.
	items := encryptor.searchableQueryFilter.FilterSearchableComparisons(stmt)
	if len(items) == 0 {
		return query, false, nil
	}
	clientSession := base.ClientSessionFromContext(ctx)
	bindSettings := queryEncryptor.PlaceholderSettingsFromClientSession(clientSession)
	// Now that we have condition expressions, perform rewriting in them.
	hashSize := []byte(fmt.Sprintf("%d", hmac.GetDefaultHashSize()))
	for _, item := range items {
		// column = 'value' ===> substring(column, 1, <HMAC_size>) = 'value'
		item.Expr.Left = &sqlparser.SubstrExpr{
			Name: item.Expr.Left.(*sqlparser.ColName),
			From: sqlparser.NewIntVal([]byte{'1'}),
			To:   sqlparser.NewIntVal(hashSize),
		}

		if rColName, ok := item.Expr.Right.(*sqlparser.ColName); ok {
			item.Expr.Right = &sqlparser.SubstrExpr{
				Name: rColName,
				From: sqlparser.NewIntVal([]byte{'1'}),
				To:   sqlparser.NewIntVal(hashSize),
			}
			continue
		}

		// MySQL have ambiguous behaviour with filtering over search data
		// query like `select table1.value, table2.value from table1 join table2 on substr(table1.searchable, 1, 33) = substr(table2.searchable, 1, 33)
		// where substr(table1.searchable, 1, 33) = X'7f6002a9335e723661b917736c3d253c07c65750839b9952801ab7f6e2a4982792'`
		// doesn't return any record, but it does work separately (with just single where search or with join over search data)
		// to escape from this ambiguity added explicit casting search hash to bytes;
		// the result expression will look like `convert(substr(searchable_column, ...), binary) = 0xFFFFF`
		// but previously we had `substr(searchable_column, ...) = X'some_value'`
		if _, ok := encryptor.coder.(*queryEncryptor.MysqlDBDataCoder); ok {
			if rVal, ok := item.Expr.Right.(*sqlparser.SQLVal); ok && rVal.Type != sqlparser.ValArg {
				item.Expr.Left = &sqlparser.ConvertExpr{
					Expr: item.Expr.Left,
					Type: &sqlparser.ConvertType{
						Type: "binary",
					},
				}

				rVal.Type = sqlparser.HexNum
			}
		}

		// substring(column, 1, <HMAC_size>) = 'value' ===> substring(column, 1, <HMAC_size>) = <HMAC('value')>
		// substring(column, 1, <HMAC_size>) = $1      ===> no changes
		err := queryEncryptor.UpdateExpressionValue(ctx, item.Expr.Right, encryptor.coder, encryptor.calculateHmac)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to update expression")
			return query, false, err
		}
		sqlVal, ok := item.Expr.Right.(*sqlparser.SQLVal)
		if !ok {
			continue
		}
		placeholderIndex, err := queryEncryptor.ParsePlaceholderIndex(sqlVal)
		if err == queryEncryptor.ErrInvalidPlaceholder {
			continue
		} else if err != nil {
			return query, false, err
		}
		bindSettings[placeholderIndex] = item.Setting
	}
	logrus.Debugln("HashQuery.OnQuery changed query")
	return base.NewOnQueryObjectFromStatement(stmt, encryptor.parser), true, nil
}

// OnBind processes bound values for prepared statements.
//
// Searchable encryption rewrites WHERE clauses with equality comparisons like this:
//
//	WHERE column = 'value'   ===>   WHERE substring(column, 1, <HMAC_size>) = <HMAC('value')>
//
// If the query is a parameterized prepared query then OnQuery() rewriting yields this:
//
//	WHERE column = $1        ===>   WHERE substring(column, 1, <HMAC_size>) = $1
//
// and actual "value" is passed via parameters, visible here in OnBind().
// If that's the case, HMAC computation should be performed for relevant values.
func (encryptor *HashQuery) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("HashQuery.OnBind")
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
	// Finally, once we know which values to replace with HMACs, do this replacement.
	return encryptor.replaceValuesWithHMACs(ctx, values, indexes)
}

func (encryptor *HashQuery) replaceValuesWithHMACs(ctx context.Context, values []base.BoundValue, placeholders []int) ([]base.BoundValue, bool, error) {
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

		data, err := values[valueIndex].GetData(encryptionSetting)
		if err != nil {
			return values, false, err
		}
		// If we can't decrypt the data and compute its HMAC, searchable encryption failed to apply.
		// Since we have already modified the query, it's likely to fail, but we can't do much about it.
		hmacHash, err := encryptor.calculateHmac(ctx, data)
		if err != nil {
			logrus.WithError(err).WithField("index", valueIndex).Debug("Failed to encrypt column")
			return values, false, err
		}
		// it is ok to ignore the error if not column setting provided
		_ = newValues[valueIndex].SetData(hmacHash, encryptionSetting)
	}
	return newValues, true, nil
}

func (encryptor *HashQuery) calculateHmac(ctx context.Context, data []byte) ([]byte, error) {
	accessContext := base.AccessContextFromContext(ctx)
	if !encryptor.decryptor.MatchDataSignature(data) {
		key, err := encryptor.keystore.GetHMACSecretKey(accessContext.GetClientID())
		if err != nil {
			logrus.WithError(err).Debugln("Can't load key for hmac")
			return nil, err
		}
		logrus.Debugln("Searchable column with raw data, replace with HMAC")
		return hmac.GenerateHMAC(key, data), nil
	}
	processorContext := base.DataProcessorContext{Context: base.SetAccessContextToContext(ctx, accessContext), Keystore: encryptor.keystore}
	decrypted, err := encryptor.decryptor.Process(data, &processorContext)
	if err != nil {
		logrus.WithError(err).Debugln("Can't decrypt data for HMAC calculation")
		return data, err
	}
	key, err := encryptor.keystore.GetHMACSecretKey(accessContext.GetClientID())
	if err != nil {
		logrus.WithError(err).Debugln("Can't load key for hmac")
		return nil, err
	}
	defer utils.ZeroizeBytes(key)
	mac := hmac.GenerateHMAC(key, decrypted)
	return mac, nil
}
