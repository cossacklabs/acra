package postgresql

import (
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/jackc/pgx/pgtype"
	"testing"
)

func Test_mapEncryptedTypeToOID(t *testing.T) {
	type args struct {
		dataType common.EncryptedType
	}
	tests := []struct {
		name  string
		args  args
		want  uint32
		want1 bool
	}{
		{"string", args{common.EncryptedType_String}, pgtype.VarcharOID, true},
		{"bytes", args{common.EncryptedType_Bytes}, pgtype.ByteaOID, true},
		{"int32", args{common.EncryptedType_Int32}, pgtype.Int4OID, true},
		{"int64", args{common.EncryptedType_Int64}, pgtype.Int8OID, true},
		{"unknown", args{common.EncryptedType_Unknown}, 0, false},
		{"different value", args{common.EncryptedType(100500)}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := mapEncryptedTypeToOID(tt.args.dataType)
			if got != tt.want {
				t.Errorf("mapEncryptedTypeToOID() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("mapEncryptedTypeToOID() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
