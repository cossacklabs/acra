package sqlparser

import (
	"fmt"
	"github.com/cossacklabs/acra/sqlparser/dependency/sqltypes"
	"io"
	"log"
	"strings"
)

// Parse parses the SQL in full and returns a Statement, which
// is the AST representation of the query. If a DDL statement
// is partially parsed but still contains a syntax error, the
// error is ignored and the DDL is returned anyway.
func Parse(sql string) (Statement, error) {
	tokenizer := NewStringTokenizer(sql)
	if yyParse(tokenizer) != 0 {
		if tokenizer.partialDDL != nil {
			log.Printf("ignoring error parsing DDL '%s': %v", sql, tokenizer.LastError)
			tokenizer.ParseTree = tokenizer.partialDDL
			return tokenizer.ParseTree, nil
		}
		return nil, tokenizer.LastError
	}
	return tokenizer.ParseTree, nil
}

// ParseStrictDDL is the same as Parse except it errors on
// partially parsed DDL statements.
func ParseStrictDDL(sql string) (Statement, error) {
	tokenizer := NewStringTokenizer(sql)
	if yyParse(tokenizer) != 0 {
		return nil, tokenizer.LastError
	}
	return tokenizer.ParseTree, nil
}

// ParseNext parses a single SQL statement from the tokenizer
// returning a Statement which is the AST representation of the query.
// The tokenizer will always read up to the end of the statement, allowing for
// the next call to ParseNext to parse any subsequent SQL statements. When
// there are no more statements to parse, a error of io.EOF is returned.
func ParseNext(tokenizer *Tokenizer) (Statement, error) {
	if tokenizer.lastChar == ';' {
		tokenizer.next()
		tokenizer.skipBlank()
	}
	if tokenizer.lastChar == eofChar {
		return nil, io.EOF
	}

	tokenizer.reset()
	tokenizer.multi = true
	if yyParse(tokenizer) != 0 {
		if tokenizer.partialDDL != nil {
			tokenizer.ParseTree = tokenizer.partialDDL
			return tokenizer.ParseTree, nil
		}
		return nil, tokenizer.LastError
	}
	return tokenizer.ParseTree, nil
}

// SplitStatement returns the first sql statement up to either a ; or EOF
// and the remainder from the given buffer
func SplitStatement(blob string) (string, string, error) {
	tokenizer := NewStringTokenizer(blob)
	tkn := 0
	for {
		tkn, _ = tokenizer.Scan()
		if tkn == 0 || tkn == ';' || tkn == eofChar {
			break
		}
	}
	if tokenizer.LastError != nil {
		return "", "", tokenizer.LastError
	}
	if tkn == ';' {
		return blob[:tokenizer.Position-2], blob[tokenizer.Position-1:], nil
	}
	return blob, "", nil
}

// SplitStatementToPieces split raw sql statement that may have multi sql pieces to sql pieces
// returns the sql pieces blob contains; or error if sql cannot be parsed
func SplitStatementToPieces(blob string) (pieces []string, err error) {
	pieces = make([]string, 0, 16)
	tokenizer := NewStringTokenizer(blob)

	tkn := 0
	var stmt string
	stmtBegin := 0
	for {
		tkn, _ = tokenizer.Scan()
		if tkn == ';' {
			stmt = blob[stmtBegin : tokenizer.Position-2]
			pieces = append(pieces, stmt)
			stmtBegin = tokenizer.Position - 1

		} else if tkn == 0 || tkn == eofChar {
			blobTail := tokenizer.Position - 2

			if stmtBegin < blobTail {
				stmt = blob[stmtBegin : blobTail+1]
				pieces = append(pieces, stmt)
			}
			break
		}
	}

	err = tokenizer.LastError
	return
}

// Format formats the node.
func (node *Select) Format(buf *TrackedBuffer) {
	buf.Myprintf("select %v%s%s%s%v from %v%v%v%v%v%v%s",
		node.Comments, node.Cache, node.Distinct, node.Hints, node.SelectExprs,
		node.From, node.Where,
		node.GroupBy, node.Having, node.OrderBy,
		node.Limit, node.Lock)
}

func (node *Select) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Comments,
		node.SelectExprs,
		node.From,
		node.Where,
		node.GroupBy,
		node.Having,
		node.OrderBy,
		node.Limit,
	)
}

// Format formats the node.
func (node *ParenSelect) Format(buf *TrackedBuffer) {
	buf.Myprintf("(%v)", node.Select)
}

func (node *ParenSelect) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Select,
	)
}

// Format formats the node.
func (node *Union) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v %s %v%v%v%s", node.Left, node.Type, node.Right,
		node.OrderBy, node.Limit, node.Lock)
}

func (node *Union) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Left,
		node.Right,
	)
}

// Format formats the node.
func (node *Stream) Format(buf *TrackedBuffer) {
	buf.Myprintf("stream %v%v from %v",
		node.Comments, node.SelectExpr, node.Table)
}

func (node *Stream) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Comments,
		node.SelectExpr,
		node.Table,
	)
}

// Format formats the node.
func (node *Insert) Format(buf *TrackedBuffer) {
	buf.Myprintf("%s %v%sinto %v%v%v %v%v%v",
		node.Action,
		node.Comments, node.Ignore,
		node.Table, node.Partitions, node.Columns, node.Rows, node.OnDup, node.Returning)
}

func (node *Insert) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Comments,
		node.Table,
		node.Columns,
		node.Rows,
		node.OnDup,
	)
}

// Format formats the node.
func (node *Update) Format(buf *TrackedBuffer) {
	buf.Myprintf("update %v%v set %v%v%v%v",
		node.Comments, node.TableExprs,
		node.Exprs, node.Where, node.OrderBy, node.Limit)
}

func (node *Update) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Comments,
		node.TableExprs,
		node.Exprs,
		node.Where,
		node.OrderBy,
		node.Limit,
	)
}

// Format formats the node.
func (node *Delete) Format(buf *TrackedBuffer) {
	buf.Myprintf("delete %v", node.Comments)
	if node.Targets != nil {
		buf.Myprintf("%v ", node.Targets)
	}
	buf.Myprintf("from %v%v%v%v%v", node.TableExprs, node.Partitions, node.Where, node.OrderBy, node.Limit)
}

func (node *Delete) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Comments,
		node.Targets,
		node.TableExprs,
		node.Where,
		node.OrderBy,
		node.Limit,
	)
}

// Format formats the node.
func (node *Set) Format(buf *TrackedBuffer) {
	if node.Scope == "" {
		buf.Myprintf("set %v%v", node.Comments, node.Exprs)
	} else {
		buf.Myprintf("set %v%s %v", node.Comments, node.Scope, node.Exprs)
	}
}

func (node *Set) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Comments,
		node.Exprs,
	)
}

// Format formats the node.
func (node *DBDDL) Format(buf *TrackedBuffer) {
	switch node.Action {
	case CreateStr:
		buf.WriteString(fmt.Sprintf("%s database %s", node.Action, node.DBName))
	case DropStr:
		exists := ""
		if node.IfExists {
			exists = " if exists"
		}
		buf.WriteString(fmt.Sprintf("%s database%s %v", node.Action, exists, node.DBName))
	}
}

// walkSubtree walks the nodes of the subtree.
func (node *DBDDL) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *DDL) Format(buf *TrackedBuffer) {
	switch node.Action {
	case CreateStr:
		if node.TableSpec == nil {
			buf.Myprintf("%s table %v", node.Action, node.NewName)
		} else {
			buf.Myprintf("%s table %v %v", node.Action, node.NewName, node.TableSpec)
		}
	case DropStr:
		exists := ""
		if node.IfExists {
			exists = " if exists"
		}
		buf.Myprintf("%s table%s %v", node.Action, exists, node.Table)
	case RenameStr:
		buf.Myprintf("%s table %v to %v", node.Action, node.Table, node.NewName)
	case AlterStr:
		if node.PartitionSpec != nil {
			buf.Myprintf("%s table %v %v", node.Action, node.Table, node.PartitionSpec)
		} else {
			buf.Myprintf("%s table %v", node.Action, node.Table)
		}
	case CreateVindexStr:
		buf.Myprintf("%s %v %v", node.Action, node.VindexSpec.Name, node.VindexSpec)
	case AddColVindexStr:
		buf.Myprintf("alter table %v %s %v (", node.Table, node.Action, node.VindexSpec.Name)
		for i, col := range node.VindexCols {
			if i != 0 {
				buf.Myprintf(", %v", col)
			} else {
				buf.Myprintf("%v", col)
			}
		}
		buf.Myprintf(")")
		if node.VindexSpec.Type.String() != "" {
			buf.Myprintf(" %v", node.VindexSpec)
		}
	case DropColVindexStr:
		buf.Myprintf("alter table %v %s %v", node.Table, node.Action, node.VindexSpec.Name)
	default:
		buf.Myprintf("%s table %v", node.Action, node.Table)
	}
}

func (node *DDL) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Table,
		node.NewName,
	)
}

// Format formats the node.
func (node *PartitionSpec) Format(buf *TrackedBuffer) {
	switch node.Action {
	case ReorganizeStr:
		buf.Myprintf("%s %v into (", node.Action, node.Name)
		var prefix string
		for _, pd := range node.Definitions {
			buf.Myprintf("%s%v", prefix, pd)
			prefix = ", "
		}
		buf.Myprintf(")")
	default:
		panic("unimplemented")
	}
}

func (node *PartitionSpec) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	if err := Walk(visit, node.Name); err != nil {
		return err
	}
	for _, def := range node.Definitions {
		if err := Walk(visit, def); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node
func (node *PartitionDefinition) Format(buf *TrackedBuffer) {
	if !node.Maxvalue {
		buf.Myprintf("partition %v values less than (%v)", node.Name, node.Limit)
	} else {
		buf.Myprintf("partition %v values less than (maxvalue)", node.Name)
	}
}

func (node *PartitionDefinition) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Name,
		node.Limit,
	)
}

// Format formats the node.
func (ts *TableSpec) Format(buf *TrackedBuffer) {
	buf.Myprintf("(\n")
	for i, col := range ts.Columns {
		if i == 0 {
			buf.Myprintf("\t%v", col)
		} else {
			buf.Myprintf(",\n\t%v", col)
		}
	}
	for _, idx := range ts.Indexes {
		buf.Myprintf(",\n\t%v", idx)
	}

	buf.Myprintf("\n)%s", strings.Replace(ts.Options, ", ", ",\n  ", -1))
}

func (ts *TableSpec) walkSubtree(visit Visit) error {
	if ts == nil {
		return nil
	}

	for _, n := range ts.Columns {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}

	for _, n := range ts.Indexes {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}

	return nil
}

// Format returns a canonical string representation of the type and all relevant options
func (ct *ColumnType) Format(buf *TrackedBuffer) {
	buf.Myprintf("%s", ct.Type)

	if ct.Length != nil && ct.Scale != nil {
		buf.Myprintf("(%v,%v)", ct.Length, ct.Scale)

	} else if ct.Length != nil {
		buf.Myprintf("(%v)", ct.Length)
	}

	if ct.EnumValues != nil {
		buf.Myprintf("(%s)", strings.Join(ct.EnumValues, ", "))
	}

	opts := make([]string, 0, 16)
	if ct.Unsigned {
		opts = append(opts, keywordStrings[UNSIGNED])
	}
	if ct.Zerofill {
		opts = append(opts, keywordStrings[ZEROFILL])
	}
	if ct.Charset != "" {
		opts = append(opts, keywordStrings[CHARACTER], keywordStrings[SET], ct.Charset)
	}
	if ct.Collate != "" {
		opts = append(opts, keywordStrings[COLLATE], ct.Collate)
	}
	if ct.NotNull {
		opts = append(opts, keywordStrings[NOT], keywordStrings[NULL])
	}
	if ct.Default != nil {
		opts = append(opts, keywordStrings[DEFAULT], String(ct.Default))
	}
	if ct.OnUpdate != nil {
		opts = append(opts, keywordStrings[ON], keywordStrings[UPDATE], String(ct.OnUpdate))
	}
	if ct.Autoincrement {
		opts = append(opts, keywordStrings[AUTO_INCREMENT])
	}
	if ct.Comment != nil {
		opts = append(opts, keywordStrings[COMMENT_KEYWORD], String(ct.Comment))
	}
	if ct.KeyOpt == colKeyPrimary {
		opts = append(opts, keywordStrings[PRIMARY], keywordStrings[KEY])
	}
	if ct.KeyOpt == colKeyUnique {
		opts = append(opts, keywordStrings[UNIQUE])
	}
	if ct.KeyOpt == colKeyUniqueKey {
		opts = append(opts, keywordStrings[UNIQUE], keywordStrings[KEY])
	}
	if ct.KeyOpt == colKeySpatialKey {
		opts = append(opts, keywordStrings[SPATIAL], keywordStrings[KEY])
	}
	if ct.KeyOpt == colKey {
		opts = append(opts, keywordStrings[KEY])
	}

	if len(opts) != 0 {
		buf.Myprintf(" %s", strings.Join(opts, " "))
	}
}

func (ct *ColumnType) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (idx *IndexDefinition) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v (", idx.Info)
	for i, col := range idx.Columns {
		if i != 0 {
			buf.Myprintf(", %v", col.Column)
		} else {
			buf.Myprintf("%v", col.Column)
		}
		if col.Length != nil {
			buf.Myprintf("(%v)", col.Length)
		}
	}
	buf.Myprintf(")")

	for _, opt := range idx.Options {
		buf.Myprintf(" %s", opt.Name)
		if opt.Using != "" {
			buf.Myprintf(" %s", opt.Using)
		} else {
			buf.Myprintf(" %v", opt.Value)
		}
	}
}

func (idx *IndexDefinition) walkSubtree(visit Visit) error {
	if idx == nil {
		return nil
	}

	for _, n := range idx.Columns {
		if err := Walk(visit, n.Column); err != nil {
			return err
		}
	}

	return nil
}

// Format formats the node.
func (ii *IndexInfo) Format(buf *TrackedBuffer) {
	if ii.Primary {
		buf.Myprintf("%s", ii.Type)
	} else {
		buf.Myprintf("%s %v", ii.Type, ii.Name)
	}
}

func (ii *IndexInfo) walkSubtree(visit Visit) error {
	return Walk(visit, ii.Name)
}

// Format formats the node. The "CREATE VINDEX" preamble was formatted in
// the containing DDL node Format, so this just prints the type, any
// parameters, and optionally the owner
func (node *VindexSpec) Format(buf *TrackedBuffer) {
	buf.Myprintf("using %v", node.Type)

	numParams := len(node.Params)
	if numParams != 0 {
		buf.Myprintf(" with ")
		for i, p := range node.Params {
			if i != 0 {
				buf.Myprintf(", ")
			}
			buf.Myprintf("%v", p)
		}
	}
}

func (node *VindexSpec) walkSubtree(visit Visit) error {
	err := Walk(visit,
		node.Name,
	)

	if err != nil {
		return err
	}

	for _, p := range node.Params {
		err := Walk(visit, p)

		if err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node VindexParam) Format(buf *TrackedBuffer) {
	buf.Myprintf("%s=%s", node.Key.String(), node.Val)
}

func (node VindexParam) walkSubtree(visit Visit) error {
	return Walk(visit,
		node.Key,
	)
}

// Format formats the node.
func (node *Show) Format(buf *TrackedBuffer) {
	if node.Type == "tables" && node.ShowTablesOpt != nil {
		opt := node.ShowTablesOpt
		if opt.DbName != "" {
			if opt.Filter != nil {
				buf.Myprintf("show %s%stables from %s %v", opt.Extended, opt.Full, opt.DbName, opt.Filter)
			} else {
				buf.Myprintf("show %s%stables from %s", opt.Extended, opt.Full, opt.DbName)
			}
		} else {
			if opt.Filter != nil {
				buf.Myprintf("show %s%stables %v", opt.Extended, opt.Full, opt.Filter)
			} else {
				buf.Myprintf("show %s%stables", opt.Extended, opt.Full)
			}
		}
		return
	}
	if node.Scope == "" {
		buf.Myprintf("show %s", node.Type)
	} else {
		buf.Myprintf("show %s %s", node.Scope, node.Type)
	}
	if node.HasOnTable() {
		buf.Myprintf(" on %v", node.OnTable)
	}
}

func (node *Show) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *ShowFilter) Format(buf *TrackedBuffer) {
	if node.Like != "" {
		buf.Myprintf("like '%s'", node.Like)
	} else {
		buf.Myprintf("where %v", node.Filter)
	}
}

func (node *ShowFilter) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *Use) Format(buf *TrackedBuffer) {
	if node.DBName.v != "" {
		buf.Myprintf("use %v", node.DBName)
	} else {
		buf.Myprintf("use")
	}
}

func (node *Use) walkSubtree(visit Visit) error {
	return Walk(visit, node.DBName)
}

// Format formats the node.
func (node *Begin) Format(buf *TrackedBuffer) {
	buf.WriteString("begin")
}

func (node *Begin) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *Commit) Format(buf *TrackedBuffer) {
	buf.WriteString("commit")
}

func (node *Commit) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *Rollback) Format(buf *TrackedBuffer) {
	buf.WriteString("rollback")
}

func (node *Rollback) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *OtherRead) Format(buf *TrackedBuffer) {
	buf.WriteString("otherread")
}

func (node *OtherRead) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *OtherAdmin) Format(buf *TrackedBuffer) {
	buf.WriteString("otheradmin")
}

func (node *OtherAdmin) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node
func (node UsingInExecuteList) Format(buf *TrackedBuffer) {

}

func (node UsingInExecuteList) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *Execute) Format(buf *TrackedBuffer) {
	if node.Using == nil {
		buf.Myprintf("execute %v", node.PreparedStatementName)
	} else {
		buf.Myprintf("execute %v using ", node.PreparedStatementName)
		var prefix string
		for _, singleUsing := range node.Using {
			buf.Myprintf("%s%v", prefix, singleUsing)
			prefix = ", "
		}
	}

}

func (node *Execute) walkSubtree(visit Visit) error {
	return Walk(visit, node.Using, node.PreparedStatementName)
}

// Format formats the node.
func (node *Prepare) Format(buf *TrackedBuffer) {
	buf.Myprintf("prepare %v from %v", node.PreparedStatementName, node.From)
}

func (node *Prepare) walkSubtree(visit Visit) error {
	return Walk(visit, node.PreparedStatementName, node.From)
}

// Format formats the node.
func (node *DeallocatePrepare) Format(buf *TrackedBuffer) {
	buf.Myprintf("deallocate prepare %v", node.PreparedStatementName)
}

func (node *DeallocatePrepare) walkSubtree(visit Visit) error {
	return Walk(visit, node.PreparedStatementName)
}

// Format formats the node.
func (node Comments) Format(buf *TrackedBuffer) {
	for _, c := range node {
		buf.Myprintf("%s ", c)
	}
}

func (node Comments) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node SelectExprs) Format(buf *TrackedBuffer) {
	var prefix string
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node SelectExprs) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *StarExpr) Format(buf *TrackedBuffer) {
	if !node.TableName.IsEmpty() {
		buf.Myprintf("%v.", node.TableName)
	}
	buf.Myprintf("*")
}

func (node *StarExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.TableName,
	)
}

// Format formats the node.
func (node *AliasedExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v", node.Expr)
	if !node.As.IsEmpty() {
		buf.Myprintf(" as %v", node.As)
	}
}

func (node *AliasedExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
		node.As,
	)
}

// Format formats the node.
func (node Nextval) Format(buf *TrackedBuffer) {
	buf.Myprintf("next %v values", node.Expr)
}

func (node Nextval) walkSubtree(visit Visit) error {
	return Walk(visit, node.Expr)
}

// Format formats the node.
func (node Columns) Format(buf *TrackedBuffer) {
	if node == nil {
		return
	}
	prefix := "("
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
	buf.WriteString(")")
}

func (node Columns) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node
func (node Partitions) Format(buf *TrackedBuffer) {
	if node == nil {
		return
	}
	prefix := " partition ("
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
	buf.WriteString(")")
}

func (node Partitions) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node TableExprs) Format(buf *TrackedBuffer) {
	var prefix string
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node TableExprs) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *AliasedTableExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v%v", node.Expr, node.Partitions)
	if !node.As.IsEmpty() {
		buf.Myprintf(" as %v", node.As)
	}
	if node.Hints != nil {
		// Hint node provides the space padding.
		buf.Myprintf("%v", node.Hints)
	}
}

func (node *AliasedTableExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
		node.As,
		node.Hints,
	)
}

// Format formats the node.
func (node TableNames) Format(buf *TrackedBuffer) {
	var prefix string
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node TableNames) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node TableName) Format(buf *TrackedBuffer) {
	if node.IsEmpty() {
		return
	}
	if !node.Qualifier.IsEmpty() {
		buf.Myprintf("%v.", node.Qualifier)
	}
	buf.Myprintf("%v", node.Name)
}

func (node TableName) walkSubtree(visit Visit) error {
	return Walk(
		visit,
		node.Name,
		node.Qualifier,
	)
}

// Format formats the node.
func (node *ParenTableExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("(%v)", node.Exprs)
}

func (node *ParenTableExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Exprs,
	)
}

// Format formats the node.
func (node JoinCondition) Format(buf *TrackedBuffer) {
	if node.On != nil {
		buf.Myprintf(" on %v", node.On)
	}
	if node.Using != nil {
		buf.Myprintf(" using %v", node.Using)
	}
}

func (node JoinCondition) walkSubtree(visit Visit) error {
	return Walk(
		visit,
		node.On,
		node.Using,
	)
}

// Format formats the node.
func (node *JoinTableExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v %s %v%v", node.LeftExpr, node.Join, node.RightExpr, node.Condition)
}

func (node *JoinTableExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.LeftExpr,
		node.RightExpr,
		node.Condition,
	)
}

// Format formats the node.
func (node *IndexHints) Format(buf *TrackedBuffer) {
	buf.Myprintf(" %sindex ", node.Type)
	prefix := "("
	for _, n := range node.Indexes {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
	buf.Myprintf(")")
}

func (node *IndexHints) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	for _, n := range node.Indexes {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *Where) Format(buf *TrackedBuffer) {
	if node == nil || node.Expr == nil {
		return
	}
	buf.Myprintf(" %s %v", node.Type, node.Expr)
}

func (node *Where) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node Exprs) Format(buf *TrackedBuffer) {
	var prefix string
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node Exprs) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *AndExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v and %v", node.Left, node.Right)
}

func (node *AndExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Left,
		node.Right,
	)
}

// Format formats the node.
func (node *OrExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v or %v", node.Left, node.Right)
}

func (node *OrExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Left,
		node.Right,
	)
}

// Format formats the node.
func (node *NotExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("not %v", node.Expr)
}

func (node *NotExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *ParenExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("(%v)", node.Expr)
}

func (node *ParenExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *ComparisonExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v %s %v", node.Left, node.Operator, node.Right)
	if node.Escape != nil {
		buf.Myprintf(" escape %v", node.Escape)
	}
}

func (node *ComparisonExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Left,
		node.Right,
		node.Escape,
	)
}

// Format formats the node.
func (node *RangeCond) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v %s %v and %v", node.Left, node.Operator, node.From, node.To)
}

func (node *RangeCond) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Left,
		node.From,
		node.To,
	)
}

// Format formats the node.
func (node *IsExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v %s", node.Expr, node.Operator)
}

func (node *IsExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *ExistsExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("exists %v", node.Subquery)
}

func (node *ExistsExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Subquery,
	)
}

// Format formats the node.
func (node *SQLVal) Format(buf *TrackedBuffer) {
	switch node.Type {
	case StrVal:
		sqltypes.MakeTrusted(sqltypes.VarBinary, node.Val).EncodeSQL(buf)
	case IntVal, FloatVal, HexNum:
		buf.Myprintf("%s", []byte(node.Val))
	case HexVal:
		buf.Myprintf("X'%s'", []byte(node.Val))
	case BitVal:
		buf.Myprintf("B'%s'", []byte(node.Val))
	case ValArg:
		buf.WriteArg(string(node.Val))
	case PgEscapeString:
		buf.Myprintf("E'%s'", sqltypes.EncodeBytesSQLWithoutQuotes(node.Val))
	default:
		panic("unexpected")
	}
	if len(node.CastType) > 0 {
		buf.Myprintf("%s", node.CastType)
	}
}

func (node *SQLVal) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *NullVal) Format(buf *TrackedBuffer) {
	buf.Myprintf("null")
}

func (node *NullVal) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node BoolVal) Format(buf *TrackedBuffer) {
	if node {
		buf.Myprintf("true")
	} else {
		buf.Myprintf("false")
	}
}

func (node BoolVal) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *ColName) Format(buf *TrackedBuffer) {
	if !node.Qualifier.IsEmpty() {
		buf.Myprintf("%v.", node.Qualifier)
	}
	buf.Myprintf("%v", node.Name)
}

func (node *ColName) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Name,
		node.Qualifier,
	)
}

// Format formats the node.
func (node ValTuple) Format(buf *TrackedBuffer) {
	buf.Myprintf("(%v)", Exprs(node))
}

func (node ValTuple) walkSubtree(visit Visit) error {
	return Walk(visit, Exprs(node))
}

// Format formats the node.
func (node *Subquery) Format(buf *TrackedBuffer) {
	buf.Myprintf("(%v)", node.Select)
}

func (node *Subquery) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Select,
	)
}

// Format formats the node.
func (node ListArg) Format(buf *TrackedBuffer) {
	buf.WriteArg(string(node))
}

func (node ListArg) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *BinaryExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v %s %v", node.Left, node.Operator, node.Right)
}

func (node *BinaryExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Left,
		node.Right,
	)
}

// Format formats the node.
func (node *UnaryExpr) Format(buf *TrackedBuffer) {
	if _, unary := node.Expr.(*UnaryExpr); unary {
		buf.Myprintf("%s %v", node.Operator, node.Expr)
		return
	}
	buf.Myprintf("%s%v", node.Operator, node.Expr)
}

func (node *UnaryExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *IntervalExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("interval %v %s", node.Expr, node.Unit)
}

func (node *IntervalExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *CollateExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v collate %s", node.Expr, node.Charset)
}

func (node *CollateExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *FuncExpr) Format(buf *TrackedBuffer) {
	var distinct string
	if node.Distinct {
		distinct = "distinct "
	}
	if !node.Qualifier.IsEmpty() {
		buf.Myprintf("%v.", node.Qualifier)
	}
	// Function names should not be back-quoted even
	// if they match a reserved word. So, print the
	// name as is.
	buf.Myprintf("%s(%s%v)", node.Name.String(), distinct, node.Exprs)
}

func (node *FuncExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Qualifier,
		node.Name,
		node.Exprs,
	)
}

// Format formats the node
func (node *GroupConcatExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("group_concat(%s%v%v%s)", node.Distinct, node.Exprs, node.OrderBy, node.Separator)
}

func (node *GroupConcatExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Exprs,
		node.OrderBy,
	)
}

// Format formats the node.
func (node *ValuesFuncExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("values(%v)", node.Name)
}

func (node *ValuesFuncExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Name,
	)
}

// Format formats the node.
func (node *SubstrExpr) Format(buf *TrackedBuffer) {

	if node.To == nil {
		buf.Myprintf("substr(%v, %v)", node.Name, node.From)
	} else {
		buf.Myprintf("substr(%v, %v, %v)", node.Name, node.From, node.To)
	}
}

func (node *SubstrExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Name,
		node.From,
		node.To,
	)
}

// Format formats the node.
func (node *ConvertExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("convert(%v, %v)", node.Expr, node.Type)
}

func (node *ConvertExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
		node.Type,
	)
}

// Format formats the node.
func (node *ConvertUsingExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("convert(%v using %s)", node.Expr, node.Type)
}

func (node *ConvertUsingExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *ConvertType) Format(buf *TrackedBuffer) {
	buf.Myprintf("%s", node.Type)
	if node.Length != nil {
		buf.Myprintf("(%v", node.Length)
		if node.Scale != nil {
			buf.Myprintf(", %v", node.Scale)
		}
		buf.Myprintf(")")
	}
	if node.Charset != "" {
		buf.Myprintf("%s %s", node.Operator, node.Charset)
	}
}

func (node *ConvertType) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node
func (node *MatchExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("match(%v) against (%v%s)", node.Columns, node.Expr, node.Option)
}

func (node *MatchExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Columns,
		node.Expr,
	)
}

// Format formats the node.
func (node *CaseExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("case ")
	if node.Expr != nil {
		buf.Myprintf("%v ", node.Expr)
	}
	for _, when := range node.Whens {
		buf.Myprintf("%v ", when)
	}
	if node.Else != nil {
		buf.Myprintf("else %v ", node.Else)
	}
	buf.Myprintf("end")
}

func (node *CaseExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	if err := Walk(visit, node.Expr); err != nil {
		return err
	}
	for _, n := range node.Whens {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return Walk(visit, node.Else)
}

// Format formats the node.
func (node *Default) Format(buf *TrackedBuffer) {
	buf.Myprintf("default")
	if node.ColName != "" {
		buf.Myprintf("(%s)", node.ColName)
	}
}

func (node *Default) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node *When) Format(buf *TrackedBuffer) {
	buf.Myprintf("when %v then %v", node.Cond, node.Val)
}

func (node *When) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Cond,
		node.Val,
	)
}

// Format formats the node.
func (node GroupBy) Format(buf *TrackedBuffer) {
	prefix := " group by "
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node GroupBy) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node OrderBy) Format(buf *TrackedBuffer) {
	prefix := " order by "
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node OrderBy) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *Order) Format(buf *TrackedBuffer) {
	if node, ok := node.Expr.(*NullVal); ok {
		buf.Myprintf("%v", node)
		return
	}
	if node, ok := node.Expr.(*FuncExpr); ok {
		if node.Name.Lowered() == "rand" {
			buf.Myprintf("%v", node)
			return
		}
	}

	buf.Myprintf("%v %s", node.Expr, node.Direction)
}

func (node *Order) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Expr,
	)
}

// Format formats the node.
func (node *Limit) Format(buf *TrackedBuffer) {
	if node == nil {
		return
	}
	buf.Myprintf(" limit ")
	if node.Offset != nil {
		buf.Myprintf("%v, ", node.Offset)
	}
	buf.Myprintf("%v", node.Rowcount)
}

func (node *Limit) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Offset,
		node.Rowcount,
	)
}

// Format formats the node.
func (node Values) Format(buf *TrackedBuffer) {
	prefix := "values "
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node Values) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node UpdateExprs) Format(buf *TrackedBuffer) {
	var prefix string
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node UpdateExprs) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *UpdateExpr) Format(buf *TrackedBuffer) {
	buf.Myprintf("%v = %v", node.Name, node.Expr)
}

func (node *UpdateExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Name,
		node.Expr,
	)
}

// Format formats the node.
func (node SetExprs) Format(buf *TrackedBuffer) {
	var prefix string
	for _, n := range node {
		buf.Myprintf("%s%v", prefix, n)
		prefix = ", "
	}
}

func (node SetExprs) walkSubtree(visit Visit) error {
	for _, n := range node {
		if err := Walk(visit, n); err != nil {
			return err
		}
	}
	return nil
}

// Format formats the node.
func (node *SetExpr) Format(buf *TrackedBuffer) {
	// We don't have to backtick set variable names.
	if node.Name.EqualString("charset") || node.Name.EqualString("names") {
		buf.Myprintf("%s %v", node.Name.String(), node.Expr)
	} else {
		buf.Myprintf("%s = %v", node.Name.String(), node.Expr)
	}
}

func (node *SetExpr) walkSubtree(visit Visit) error {
	if node == nil {
		return nil
	}
	return Walk(
		visit,
		node.Name,
		node.Expr,
	)
}

// Format formats the node.
func (node OnDup) Format(buf *TrackedBuffer) {
	if node == nil {
		return
	}
	buf.Myprintf(" on duplicate key update %v", UpdateExprs(node))
}

func (node OnDup) walkSubtree(visit Visit) error {
	return Walk(visit, UpdateExprs(node))
}

// Format formats the node.
func (node Returning) Format(buf *TrackedBuffer) {
	if node == nil {
		return
	}
	buf.Myprintf(" returning %v", Exprs(node))
}

func (node Returning) walkSubtree(visit Visit) error {
	return Walk(visit, Exprs(node))
}

// Format formats the node.
func (node ColIdent) Format(buf *TrackedBuffer) {
	if node.wrapWithQuotes {
		// print as is in quotes
		buf.Myprintf(`"%s"`, node.val)
	} else {
		formatID(buf, node.val, node.Lowered())
	}

}

func (node ColIdent) walkSubtree(visit Visit) error {
	return nil
}

// Format formats the node.
func (node TableIdent) Format(buf *TrackedBuffer) {
	if node.wrapWithQuotes {
		// print as is in quotes
		buf.Myprintf(`"%s"`, node.v)
	} else {
		formatID(buf, node.v, strings.ToLower(node.v))
	}

}

func (node TableIdent) walkSubtree(visit Visit) error {
	return nil
}
