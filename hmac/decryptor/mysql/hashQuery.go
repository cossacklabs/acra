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

	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	encryptor_base "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/mysql"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/cossacklabs/acra/utils"
)

// HashDecryptStore that used by HashQuery
type HashDecryptStore interface {
	keystore.HmacKeyStore
	keystore.DataEncryptorKeyStore
}

// HashQuery calculate hmac for data inside AcraStruct and change WHERE conditions to support searchable encryption
type HashQuery struct {
	keystore              HashDecryptStore
	searchableQueryFilter *mysql.SearchableQueryFilter
	coder                 encryptor_base.DBDataCoder
	decryptor             base.ExtendedDataProcessor
	parser                *sqlparser.Parser
	schemaStore           config.TableSchemaStore
}

// NewHashQuery return HashQuery with coder for mysql
func NewHashQuery(keystore HashDecryptStore, schemaStore config.TableSchemaStore, processor base.ExtendedDataProcessor) *HashQuery {
	searchableQueryFilter := mysql.NewSearchableQueryFilter(schemaStore, encryptor_base.QueryFilterModeSearchableEncryption)
	return &HashQuery{keystore: keystore, coder: &mysql.DBDataCoder{}, searchableQueryFilter: searchableQueryFilter, decryptor: processor, schemaStore: schemaStore}
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
func (encryptor *HashQuery) OnQuery(ctx context.Context, query mysql.OnQueryObject) (mysql.OnQueryObject, bool, error) {
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
	// Now that we have condition expressions, perform rewriting in them.
	hashSize := []byte(fmt.Sprintf("%d", hmac.GetDefaultHashSize()))
	changed := len(items) > 0
	// clientSession/bindSettings are only needed to track WHERE-comparison placeholders, so fetch
	// them lazily: this keeps the non-searchable and GROUP-BY-only paths allocation-free and avoids
	// dereferencing a nil session.
	var bindSettings map[int]config.ColumnEncryptionSetting
	if len(items) > 0 {
		clientSession := base.ClientSessionFromContext(ctx)
		bindSettings = encryptor_base.PlaceholderSettingsFromClientSession(clientSession)
	}
	for _, item := range items {
		if !item.Setting.IsSearchable() {
			continue
		}

		// column = 'value' ===> substring(column, 1, <HMAC_size>) = 'value'
		item.Expr.Left = &sqlparser.SubstrExpr{
			Name: item.Expr.Left.(*sqlparser.ColName),
			From: sqlparser.NewIntVal([]byte{'1'}),
			To:   sqlparser.NewIntVal(hashSize),
		}

		encryptor.searchableQueryFilter.ChangeSearchableOperator(item.Expr)

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
		if rVal, ok := item.Expr.Right.(*sqlparser.SQLVal); ok && rVal.Type != sqlparser.ValArg {
			item.Expr.Left = &sqlparser.ConvertExpr{
				Expr: item.Expr.Left,
				Type: &sqlparser.ConvertType{
					Type: "binary",
				},
			}

			rVal.Type = sqlparser.HexNum
		}

		// substring(column, 1, <HMAC_size>) = 'value' ===> substring(column, 1, <HMAC_size>) = <HMAC('value')>
		// substring(column, 1, <HMAC_size>) = $1      ===> no changes
		err := mysql.UpdateExpressionValue(ctx, item.Expr.Right, encryptor.coder, item.Setting, encryptor.calculateHmac)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to update expression")
			return query, false, err
		}
		sqlVal, ok := item.Expr.Right.(*sqlparser.SQLVal)
		if !ok {
			continue
		}
		placeholderIndex, err := mysql.ParsePlaceholderIndex(sqlVal)
		if err == encryptor_base.ErrInvalidPlaceholder {
			continue
		} else if err != nil {
			return query, false, err
		}
		bindSettings[placeholderIndex] = item.Setting
	}

	// Searchable columns are stored as <HMAC prefix>||<ciphertext>, where the HMAC prefix is
	// DETERMINISTIC (equal plaintext -> equal prefix) but the ciphertext is randomized per row.
	// So GROUP BY on the raw column groups by the random ciphertext and never collapses equal
	// plaintexts, silently breaking aggregation. (SELECT DISTINCT on a searchable column shares the
	// same root cause and is a tracked follow-up; only GROUP BY is rewritten here.) Rewrite GROUP BY
	// on a searchable column to
	// group by its hash prefix instead:
	//
	//	GROUP BY column   ===>   GROUP BY substring(column, 1, <HMAC_size>)
	//
	// and wrap bare references to the grouped column in the SELECT list / ORDER BY in ANY_VALUE()
	// so the query stays valid under ONLY_FULL_GROUP_BY (every row in a group shares the same
	// plaintext, so any representative decrypts to the correct value).
	if sel, ok := stmt.(*sqlparser.Select); ok {
		if encryptor.rewriteSearchableGroupBy(sel, hashSize) {
			changed = true
		}
	}

	if !changed {
		return query, false, nil
	}

	logrus.Debugln("HashQuery.OnQuery changed query")
	return mysql.NewOnQueryObjectFromStatement(stmt, encryptor.parser), true, nil
}

// rewriteSearchableGroupBy rewrites GROUP BY on searchable columns to group by their deterministic
// HMAC prefix (substring(col, 1, hashSize)) and wraps bare references to those columns in the
// SELECT list and ORDER BY with ANY_VALUE() to satisfy ONLY_FULL_GROUP_BY. It returns true when the
// statement was modified. ORDER BY on a searchable column is made valid but is ordered by the hash
// (not the plaintext), since searchable encryption is not order-preserving.
func (encryptor *HashQuery) rewriteSearchableGroupBy(sel *sqlparser.Select, hashSize []byte) bool {
	if len(sel.GroupBy) == 0 {
		return false
	}

	type columnKey struct{ table, name string }
	grouped := make(map[columnKey]bool)

	// resolve returns the (table, column) key for a ColName when it maps to a searchable column.
	resolve := func(col *sqlparser.ColName) (columnKey, bool) {
		info, err := mysql.FindColumnInfo(sel.From, col, encryptor.schemaStore)
		if err != nil {
			return columnKey{}, false
		}
		setting := mysql.GetColumnSetting(col, info.Table, encryptor.schemaStore)
		if setting == nil || !setting.IsSearchable() {
			return columnKey{}, false
		}
		return columnKey{table: info.Table, name: info.Name}, true
	}

	substr := func(col *sqlparser.ColName) *sqlparser.SubstrExpr {
		return &sqlparser.SubstrExpr{
			Name: col,
			From: sqlparser.NewIntVal([]byte("1")),
			To:   sqlparser.NewIntVal(hashSize),
		}
	}

	changed := false
	for i, expr := range sel.GroupBy {
		col, ok := expr.(*sqlparser.ColName)
		if !ok {
			continue
		}
		key, ok := resolve(col)
		if !ok {
			continue
		}
		grouped[key] = true
		sel.GroupBy[i] = substr(col)
		changed = true
	}
	if !changed {
		return false
	}

	// anyValue wraps a reference to a grouped searchable column in ANY_VALUE(col) so it is not a
	// bare non-aggregated column under ONLY_FULL_GROUP_BY. Returns (wrapped, true) only for a
	// grouped searchable column.
	anyValue := func(col *sqlparser.ColName) (sqlparser.Expr, bool) {
		key, ok := resolve(col)
		if !ok || !grouped[key] {
			return nil, false
		}
		return &sqlparser.FuncExpr{
			Name:  sqlparser.NewColIdent("ANY_VALUE"),
			Exprs: sqlparser.SelectExprs{&sqlparser.AliasedExpr{Expr: col}},
		}, true
	}

	for _, se := range sel.SelectExprs {
		aliased, ok := se.(*sqlparser.AliasedExpr)
		if !ok {
			continue
		}
		col, ok := aliased.Expr.(*sqlparser.ColName)
		if !ok {
			continue
		}
		if wrapped, ok := anyValue(col); ok {
			// preserve the client-visible column name (default to the column name when unaliased)
			if aliased.As.IsEmpty() {
				aliased.As = col.Name
			}
			aliased.Expr = wrapped
		}
	}

	for _, order := range sel.OrderBy {
		col, ok := order.Expr.(*sqlparser.ColName)
		if !ok {
			continue
		}
		if wrapped, ok := anyValue(col); ok {
			order.Expr = wrapped
		}
	}

	return true
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
		if !item.Setting.IsSearchable() {
			continue
		}

		switch value := item.Expr.Right.(type) {
		case *sqlparser.SQLVal:
			var err error
			index, err := mysql.ParsePlaceholderIndex(value)
			if err != nil {
				return values, false, err
			}
			if index >= len(values) {
				logrus.WithFields(logrus.Fields{"placeholder": value.Val, "index": index, "values": len(values)}).
					Warning("Invalid placeholder index")
				return values, false, encryptor_base.ErrInvalidPlaceholder
			}
			indexes = append(indexes, index)
		}
	}

	bindData := mysql.ParseSearchQueryPlaceholdersSettings(statement, encryptor.schemaStore)
	if len(bindData) > len(indexes) {
		return values, false, nil
	}

	// Finally, once we know which values to replace with HMACs, do this replacement.
	return encryptor.replaceValuesWithHMACs(ctx, values, indexes, bindData)
}

func (encryptor *HashQuery) replaceValuesWithHMACs(ctx context.Context, values []base.BoundValue, placeholders []int, bindData map[int]config.ColumnEncryptionSetting) ([]base.BoundValue, bool, error) {
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
