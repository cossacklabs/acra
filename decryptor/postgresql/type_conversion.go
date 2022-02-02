package postgresql

import (
	"github.com/cossacklabs/acra/pseudonymization/common"
	"github.com/jackc/pgx/pgtype"
)

func mapTokenTypeToOID(tokenType common.TokenType) (uint32, bool) {
	switch tokenType {
	case common.TokenType_Email:
		return pgtype.VarcharOID, true
	case common.TokenType_String:
		return pgtype.TextOID, true
	case common.TokenType_Int32:
		return pgtype.Int4OID, true
	case common.TokenType_Int64:
		return pgtype.Int8OID, true
	}
	return 0, false
}
