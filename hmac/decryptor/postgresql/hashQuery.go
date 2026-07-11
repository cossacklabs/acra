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

	pg_query "github.com/cossacklabs/pg_query_go/v5"
	"github.com/sirupsen/logrus"

	"github.com/cossacklabs/acra/decryptor/base"
	queryEncryptor "github.com/cossacklabs/acra/encryptor/base"
	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/encryptor/postgresql"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/keystore"
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
	searchableQueryFilter *postgresql.SearchableQueryFilter
	coder                 *postgresql.PgQueryDBDataCoder
	decryptor             base.ExtendedDataProcessor
	schemaStore           config.TableSchemaStore
}

// NewHashQuery return HashQuery with coder for postgresql
func NewHashQuery(keystore HashDecryptStore, schemaStore config.TableSchemaStore, processor base.ExtendedDataProcessor) *HashQuery {
	searchableQueryFilter := postgresql.NewSearchableQueryFilter(schemaStore, queryEncryptor.QueryFilterModeSearchableEncryption)
	return &HashQuery{keystore: keystore, coder: &postgresql.PgQueryDBDataCoder{}, searchableQueryFilter: searchableQueryFilter, decryptor: processor, schemaStore: schemaStore}
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
func (encryptor *HashQuery) OnQuery(ctx context.Context, query postgresql.OnQueryObject) (postgresql.OnQueryObject, bool, error) {
	logrus.Debugln("HashQuery.OnQuery")

	parseResult, err := query.Statement()
	if err != nil || len(parseResult.Stmts) == 0 {
		logrus.Debugln("Failed to parse incoming query", err)
		return query, false, nil
	}

	// Extract the subexpressions that we are interested in for searchable encryption.
	// The list might be empty for non-SELECT queries or for non-eligible SELECTs.
	// In that case we don't have any more work to do here.
	items := encryptor.searchableQueryFilter.FilterSearchableComparisons(parseResult)
	changed := len(items) > 0
	// clientSession/bindSettings are only needed to track WHERE-comparison placeholders; fetch them
	// lazily so the GROUP-BY-only and non-searchable paths stay allocation-free and nil-safe.
	var bindSettings map[int]config.ColumnEncryptionSetting
	if len(items) > 0 {
		clientSession := base.ClientSessionFromContext(ctx)
		bindSettings = queryEncryptor.PlaceholderSettingsFromClientSession(clientSession)
	}
	// Now that we have condition expressions, perform rewriting in them.
	for _, item := range items {
		if !item.Setting.IsSearchable() {
			continue
		}

		// column = 'value' ===> substring(column, 1, <HMAC_size>) = 'value'
		item.Expr.Lexpr = getSubstrFuncNode(item.Expr.Lexpr)

		encryptor.searchableQueryFilter.ChangeSearchableOperator(item.Expr)

		if item.Expr.Rexpr.GetColumnRef() != nil {
			item.Expr.Rexpr = getSubstrFuncNode(item.Expr.Rexpr)
		}

		// substring(column, 1, <HMAC_size>) = 'value' ===> substring(column, 1, <HMAC_size>) = <HMAC('value')>
		// substring(column, 1, <HMAC_size>) = $1      ===> no changes
		aConst := item.Expr.Rexpr.GetAConst()
		if typeCast := item.Expr.Rexpr.GetTypeCast(); typeCast != nil {
			aConst = typeCast.GetArg().GetAConst()
		}

		err := postgresql.UpdateExpressionValue(ctx, aConst, encryptor.coder, item.Setting, encryptor.calculateHmac)
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

	// Searchable columns are stored as <deterministic HMAC prefix>||<randomized ciphertext>. GROUP
	// BY on the raw column groups by the random ciphertext and never collapses equal plaintexts,
	// silently breaking aggregation. Rewrite GROUP BY on a searchable column to group by its hash
	// prefix (substring(col, 1, <HMAC_size>)) and wrap bare references to it in the target list /
	// ORDER BY with (array_agg(col))[1] (PostgreSQL requires an aggregate for non-grouped columns and
	// has no bytea min(); every row in a group shares the plaintext, so the representative decrypts
	// correctly).
	if selectStmt := parseResult.Stmts[0].Stmt.GetSelectStmt(); selectStmt != nil {
		if encryptor.rewriteSearchableGroupBy(selectStmt) {
			changed = true
		}
	}

	if !changed {
		return query, false, nil
	}
	logrus.Debugln("HashQuery.OnQuery changed query")
	return postgresql.NewOnQueryObjectFromStatement(parseResult), true, nil
}

// arrayAggFuncName is the PostgreSQL aggregate used by firstOfGroupNode to wrap a grouped searchable
// column. PostgreSQL has no min()/max() for bytea and any_value() requires PostgreSQL 16+, so
// (array_agg(col))[1] is used to return a representative row's value portably across supported
// PostgreSQL versions; every row in a group shares the plaintext, so it decrypts correctly.
const arrayAggFuncName = "array_agg"

// rewriteSearchableGroupBy rewrites GROUP BY on searchable columns to group by their deterministic
// HMAC prefix (substr(col, 1, hashSize)) and wraps bare references to those columns in the target
// list and ORDER BY with (array_agg(col))[1]. Returns true when the statement was modified. ORDER BY
// on a searchable column becomes valid but is ordered by the hash, not the plaintext, since
// searchable encryption is not order-preserving. Scope mirrors the MySQL implementation: only the
// top-level SELECT is handled (not subqueries/CTEs/UNION/INSERT...SELECT), and GROUP BY by ordinal
// and SELECT DISTINCT are known follow-ups.
func (encryptor *HashQuery) rewriteSearchableGroupBy(selectStmt *pg_query.SelectStmt) bool {
	if len(selectStmt.GroupClause) == 0 {
		return false
	}
	fromClause := selectStmt.FromClause

	type columnKey struct{ table, name string }
	grouped := make(map[columnKey]bool)

	resolve := func(colRef *pg_query.ColumnRef) (columnKey, bool) {
		info, err := postgresql.FindColumnInfo(fromClause, colRef, encryptor.schemaStore)
		if err != nil {
			return columnKey{}, false
		}
		setting := postgresql.GetColumnSetting(colRef, info.Table, encryptor.schemaStore)
		if setting == nil || !setting.IsSearchable() {
			return columnKey{}, false
		}
		return columnKey{table: info.Table, name: info.Name}, true
	}

	changed := false
	for i, node := range selectStmt.GroupClause {
		colRef := node.GetColumnRef()
		if colRef == nil {
			continue
		}
		key, ok := resolve(colRef)
		if !ok {
			continue
		}
		grouped[key] = true
		selectStmt.GroupClause[i] = getSubstrFuncNode(node)
		changed = true
	}
	if !changed {
		return false
	}

	for _, node := range selectStmt.TargetList {
		resTarget := node.GetResTarget()
		if resTarget == nil {
			continue
		}
		colRef := resTarget.GetVal().GetColumnRef()
		if colRef == nil {
			continue
		}
		key, ok := resolve(colRef)
		if !ok || !grouped[key] {
			continue
		}
		if resTarget.Name == "" {
			// preserve the client-visible column name (the wrapped expr would otherwise be unnamed)
			resTarget.Name = columnRefName(colRef)
		}
		resTarget.Val = firstOfGroupNode(resTarget.Val)
	}

	for _, node := range selectStmt.SortClause {
		sortBy := node.GetSortBy()
		if sortBy == nil {
			continue
		}
		colRef := sortBy.GetNode().GetColumnRef()
		if colRef == nil {
			continue
		}
		key, ok := resolve(colRef)
		if !ok || !grouped[key] {
			continue
		}
		sortBy.Node = firstOfGroupNode(sortBy.Node)
	}

	return true
}

// aggFuncNode builds a function-call node `name(arg)`.
func aggFuncNode(name string, arg *pg_query.Node) *pg_query.Node {
	return &pg_query.Node{
		Node: &pg_query.Node_FuncCall{
			FuncCall: &pg_query.FuncCall{
				Funcname: []*pg_query.Node{
					{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: name}}},
				},
				Args:       []*pg_query.Node{arg},
				Funcformat: pg_query.CoercionForm_COERCE_EXPLICIT_CALL,
			},
		},
	}
}

// firstOfGroupNode builds `(array_agg(arg))[1]` — an aggregate returning one representative value
// from the group. Used to wrap a grouped searchable (bytea) column, for which PostgreSQL has no
// min()/max() aggregate.
func firstOfGroupNode(arg *pg_query.Node) *pg_query.Node {
	return &pg_query.Node{
		Node: &pg_query.Node_AIndirection{
			AIndirection: &pg_query.A_Indirection{
				Arg: aggFuncNode(arrayAggFuncName, arg),
				Indirection: []*pg_query.Node{
					{Node: &pg_query.Node_AIndices{AIndices: &pg_query.A_Indices{
						Uidx: &pg_query.Node{Node: &pg_query.Node_AConst{AConst: &pg_query.A_Const{
							Val: &pg_query.A_Const_Ival{Ival: &pg_query.Integer{Ival: 1}},
						}}},
					}}},
				},
			},
		},
	}
}

// columnRefName returns the unqualified column name from a ColumnRef.
func columnRefName(colRef *pg_query.ColumnRef) string {
	fields := colRef.GetFields()
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1].GetString_().GetSval()
}

func getSubstrFuncNode(column *pg_query.Node) *pg_query.Node {
	return &pg_query.Node{
		Node: &pg_query.Node_FuncCall{
			FuncCall: &pg_query.FuncCall{
				Funcname: []*pg_query.Node{
					{
						Node: &pg_query.Node_String_{
							String_: &pg_query.String{
								Sval: postgresql.SubstrFuncName,
							},
						},
					},
				},
				Args: []*pg_query.Node{
					&*column,
					{
						Node: &pg_query.Node_AConst{
							AConst: &pg_query.A_Const{
								Val: &pg_query.A_Const_Ival{
									Ival: &pg_query.Integer{
										Ival: 1,
									},
								},
							},
						},
					},
					{
						Node: &pg_query.Node_AConst{
							AConst: &pg_query.A_Const{
								Val: &pg_query.A_Const_Ival{
									Ival: &pg_query.Integer{
										Ival: int32(hmac.GetDefaultHashSize()),
									},
								},
							},
						},
					},
				},
				Funcformat: pg_query.CoercionForm_COERCE_EXPLICIT_CALL,
			},
		},
	}
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
func (encryptor *HashQuery) OnBind(ctx context.Context, parseResult *pg_query.ParseResult, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("HashQuery.OnBind")

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
		if !item.Setting.IsSearchable() {
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
			return values, false, queryEncryptor.ErrInvalidPlaceholder
		}
		indexes = append(indexes, index)
	}

	bindData := postgresql.ParseSearchQueryPlaceholdersSettings(parseResult, encryptor.schemaStore)
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
