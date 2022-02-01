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
	"github.com/cossacklabs/acra/utils"
	"strconv"
	"strings"

	"github.com/cossacklabs/acra/decryptor/base"
	queryEncryptor "github.com/cossacklabs/acra/encryptor"
	"github.com/cossacklabs/acra/encryptor/config"
	"github.com/cossacklabs/acra/hmac"
	"github.com/cossacklabs/acra/keystore"
	"github.com/cossacklabs/acra/sqlparser"
	"github.com/sirupsen/logrus"
)

// HashDecryptStore that used by HashQuery
type HashDecryptStore interface {
	keystore.HmacKeyStore
	keystore.DataEncryptorKeyStore
}

// HashQuery calculate hmac for data inside AcraStruct and change WHERE conditions to support searchable encryption
type HashQuery struct {
	keystore    HashDecryptStore
	coder       queryEncryptor.DBDataCoder
	schemaStore config.TableSchemaStore
	decryptor   base.ExtendedDataProcessor
	parser      *sqlparser.Parser
}

// NewPostgresqlHashQuery return HashQuery with coder for postgresql
func NewPostgresqlHashQuery(keystore HashDecryptStore, schemaStore config.TableSchemaStore, decryptor base.ExtendedDataProcessor) *HashQuery {
	return &HashQuery{keystore: keystore, coder: &queryEncryptor.PostgresqlDBDataCoder{}, schemaStore: schemaStore, decryptor: decryptor}
}

// NewMysqlHashQuery return HashQuery with coder for mysql
func NewMysqlHashQuery(keystore HashDecryptStore, schemaStore config.TableSchemaStore, decryptor base.ExtendedDataProcessor) *HashQuery {
	return &HashQuery{keystore: keystore, coder: &queryEncryptor.MysqlDBDataCoder{}, schemaStore: schemaStore, decryptor: decryptor}
}

// ID returns name of this QueryObserver.
func (encryptor *HashQuery) ID() string {
	return "HashQuery"
}

func (encryptor *HashQuery) filterSearchableComparisons(statement sqlparser.Statement) []*sqlparser.ComparisonExpr {
	// We are interested only in SELECT statements which access at least one encryptable table.
	// If that's not the case, we have nothing to do here.
	defaultTable, aliasedTables := encryptor.filterInterestingTables(statement)
	if len(aliasedTables) == 0 {
		logrus.Debugln("No encryptable tables in search query")
		return nil
	}
	// Now take a closer look at WHERE clauses of the statement. We need only expressions
	// which are simple equality comparisons, like "WHERE column = value".
	exprs := encryptor.filterComparisonExprs(statement)
	if len(exprs) == 0 {
		logrus.Debugln("No eligible comparisons in search query")
		return nil
	}
	// And among those expressions, not all may refer to columns with searchable encryption
	// enabled for them. Leave only those expressions which are searchable.
	exprs = encryptor.filterSerchableComparisons(exprs, defaultTable, aliasedTables)
	if len(exprs) == 0 {
		logrus.Debugln("No searchable comparisons in search query")
		return nil
	}
	return exprs
}

func (encryptor *HashQuery) filterInterestingTables(statement sqlparser.Statement) (*queryEncryptor.AliasedTableName, queryEncryptor.AliasToTableMap) {
	// We are interested only in SELECT statements.
	selectStatement, ok := statement.(*sqlparser.Select)
	if !ok {
		return nil, nil
	}
	// Not all SELECT statements refer to tables at all.
	tables := queryEncryptor.GetTablesWithAliases(selectStatement.From)
	if len(tables) == 0 {
		return nil, nil
	}
	// And even then, we can work only with tables that we have an encryption schema for.
	var encryptableTables []*queryEncryptor.AliasedTableName
	for _, table := range tables {
		if v := encryptor.schemaStore.GetTableSchema(table.TableName.Name.String()); v != nil {
			encryptableTables = append(encryptableTables, table)
		}
	}
	if len(encryptableTables) == 0 {
		return nil, nil
	}
	return tables[0], queryEncryptor.NewAliasToTableMapFromTables(encryptableTables)
}

func (encryptor *HashQuery) filterComparisonExprs(statement sqlparser.Statement) []*sqlparser.ComparisonExpr {
	// Walk through WHERE clauses of a SELECT statements...
	whereExprs, err := getWhereStatements(statement)
	if err != nil {
		logrus.WithError(err).Debugln("Failed to extract WHERE clauses")
		return nil
	}
	// ...and find all eligible comparison expressions in them.
	var exprs []*sqlparser.ComparisonExpr
	for _, whereExpr := range whereExprs {
		comparisonExprs, err := getEqualComparisonExprs(whereExpr)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to extract comparison expressions")
			return nil
		}
		exprs = append(exprs, comparisonExprs...)
	}
	return exprs
}

func (encryptor *HashQuery) filterSerchableComparisons(exprs []*sqlparser.ComparisonExpr, defaultTable *queryEncryptor.AliasedTableName, aliasedTables queryEncryptor.AliasToTableMap) []*sqlparser.ComparisonExpr {
	filtered := make([]*sqlparser.ComparisonExpr, 0, len(exprs))
	for _, expr := range exprs {
		// Leave out comparisons of columns which do not have a schema after alias resolution.
		column := expr.Left.(*sqlparser.ColName)
		schema := encryptor.getTableSchemaOfColumn(column, defaultTable, aliasedTables)
		if schema == nil {
			continue
		}
		// Also leave out those columns which are not searchable.
		columnName := column.Name.String()
		encryptionSetting := schema.GetColumnEncryptionSettings(columnName)
		if encryptionSetting == nil || !encryptionSetting.IsSearchable() {
			continue
		}
		filtered = append(filtered, expr)
	}
	return filtered
}

func (encryptor *HashQuery) getTableSchemaOfColumn(column *sqlparser.ColName, defaultTable *queryEncryptor.AliasedTableName, aliasedTables queryEncryptor.AliasToTableMap) config.TableSchema {
	if column.Qualifier.Qualifier.IsEmpty() {
		return encryptor.schemaStore.GetTableSchema(defaultTable.TableName.Name.String())
	}
	tableName := aliasedTables[column.Qualifier.Name.String()]
	return encryptor.schemaStore.GetTableSchema(tableName)
}

// OnQuery processes query text before database sees it.
//
// Searchable encryption rewrites WHERE clauses with equality comparisons like this:
//
//     WHERE column = 'value'   ===>   WHERE substring(column, 1, <HMAC_size>) = <HMAC('value')>
//
// If the query is a parameterized prepared query then OnQuery() rewriting yields this:
//
//     WHERE column = $1        ===>   WHERE substring(column, 1, <HMAC_size>) = $1
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
	exprs := encryptor.filterSearchableComparisons(stmt)
	if len(exprs) == 0 {
		return query, false, nil
	}
	// Now that we have condition expressions, perform rewriting in them.
	hashSize := []byte(fmt.Sprintf("%d", hmac.GetDefaultHashSize()))
	for _, expr := range exprs {
		// column = 'value' ===> substring(column, 1, <HMAC_size>) = 'value'
		expr.Left = &sqlparser.SubstrExpr{
			Name: expr.Left.(*sqlparser.ColName),
			From: sqlparser.NewIntVal([]byte{'1'}),
			To:   sqlparser.NewIntVal(hashSize),
		}

		// substring(column, 1, <HMAC_size>) = 'value' ===> substring(column, 1, <HMAC_size>) = <HMAC('value')>
		// substring(column, 1, <HMAC_size>) = $1      ===> no changes
		err := queryEncryptor.UpdateExpressionValue(ctx, expr.Right, encryptor.coder, encryptor.calculateHmac)
		if err != nil {
			logrus.WithError(err).Debugln("Failed to update expression")
			return query, false, err
		}
	}
	logrus.Debugln("HashQuery.OnQuery changed query")
	return base.NewOnQueryObjectFromStatement(stmt, encryptor.parser), true, nil
}

// OnBind processes bound values for prepared statements.
//
// Searchable encryption rewrites WHERE clauses with equality comparisons like this:
//
//     WHERE column = 'value'   ===>   WHERE substring(column, 1, <HMAC_size>) = <HMAC('value')>
//
// If the query is a parameterized prepared query then OnQuery() rewriting yields this:
//
//     WHERE column = $1        ===>   WHERE substring(column, 1, <HMAC_size>) = $1
//
// and actual "value" is passed via parameters, visible here in OnBind().
// If that's the case, HMAC computation should be performed for relevant values.
func (encryptor *HashQuery) OnBind(ctx context.Context, statement sqlparser.Statement, values []base.BoundValue) ([]base.BoundValue, bool, error) {
	logrus.Debugln("HashQuery.OnBind")
	// Extract the subexpressions that we are interested in for searchable encryption.
	// The list might be empty for non-SELECT queries or for non-eligible SELECTs.
	// In that case we don't have any more work to do here.
	exprs := encryptor.filterSearchableComparisons(statement)
	if len(exprs) == 0 {
		return values, false, nil
	}
	// Now that we have expressions, analyze them to look for involved placeholders
	// and map them onto values that we need to update.
	placeholders := make([]int, 0, len(values))
	for _, expr := range exprs {
		switch value := expr.Right.(type) {
		case *sqlparser.SQLVal:
			var err error
			placeholders, err = encryptor.updatePlaceholderList(placeholders, values, value)
			if err != nil {
				return values, false, err
			}
		}
	}
	// Finally, once we know which values to replace with HMACs, do this replacement.
	return encryptor.replaceValuesWithHMACs(ctx, values, placeholders)
}

func (encryptor *HashQuery) updatePlaceholderList(placeholders []int, values []base.BoundValue, placeholder *sqlparser.SQLVal) ([]int, error) {
	updateMapByPlaceholderPart := func(part string) ([]int, error) {
		text := string(placeholder.Val)
		index, err := strconv.Atoi(strings.TrimPrefix(text, part))
		if err != nil {
			logrus.WithField("placeholder", text).WithError(err).Warning("Cannot parse placeholder")
			return nil, err
		}
		// Placeholders use 1-based indexing and "values" (Go slice) are 0-based.
		index--
		if index >= len(values) {
			logrus.WithFields(logrus.Fields{"placeholder": text, "index": index, "values": len(values)}).
				Warning("Invalid placeholder index")
			return nil, queryEncryptor.ErrInvalidPlaceholder
		}
		placeholders = append(placeholders, index)
		return placeholders, nil
	}

	switch placeholder.Type {
	case sqlparser.PgPlaceholder:
		// PostgreSQL placeholders look like "$1". Parse the number out of them.
		return updateMapByPlaceholderPart("$")
	case sqlparser.ValArg:
		// MySQL placeholders look like ":v1". Parse the number out of them.
		return updateMapByPlaceholderPart(":v")
	}
	return placeholders, nil
}

func (encryptor *HashQuery) replaceValuesWithHMACs(ctx context.Context, values []base.BoundValue, placeholders []int) ([]base.BoundValue, bool, error) {
	// If there are no interesting placholder positions then we don't have to process anything.
	if len(placeholders) == 0 {
		return values, false, nil
	}
	// Otherwise, decrypt values at positions indicated by placeholders and replace them with their HMACs.
	newValues := make([]base.BoundValue, len(values))
	copy(newValues, values)

	for _, valueIndex := range placeholders {
		format := values[valueIndex].Format()

		data, err := values[valueIndex].GetData(nil)
		if err != nil {
			return values, false, err
		}
		switch format {
		case base.BinaryFormat:
			// If we can't decrypt the data and compute its HMAC, searchable encryption failed to apply.
			// Since we have already modified the query, it's likely to fail, but we can't do much about it.
			hmacHash, err := encryptor.calculateHmac(ctx, data)
			if err != nil {
				logrus.WithError(err).WithField("index", valueIndex).Debug("Failed to encrypt column")
				return values, false, err
			}
			// it is ok to ignore the error if not column setting provided
			_ = newValues[valueIndex].SetData(hmacHash, nil)

		// TODO(ilammy, 2020-10-14): implement support for base.BindText
		// We should parse and decode the data, convert that into HMAC instead,
		// and then either force binary format or reencode the data back into text.

		default:
			logrus.WithFields(logrus.Fields{"format": format, "index": valueIndex}).
				Warning("Parameter format not supported, skipping")
		}
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
