package postgresql

import (
	"github.com/jackc/pgx/pgtype"
	"testing"
)

func Test_mapEncryptedTypeToOID(t *testing.T) {
	type args struct {
		dataTypeID uint32
	}
	tests := []struct {
		name  string
		args  args
		want  uint32
		want1 bool
	}{
		{"string", args{pgtype.TextOID}, pgtype.TextOID, true},
		{"bytes", args{pgtype.ByteaOID}, pgtype.ByteaOID, true},
		{"int32", args{pgtype.Int4OID}, pgtype.Int4OID, true},
		{"int64", args{pgtype.Int8OID}, pgtype.Int8OID, true},
		{"unknown", args{0}, 0, false},
		{"different value", args{100500}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := mapEncryptedTypeToOID(tt.args.dataTypeID)
			if got != tt.want {
				t.Errorf("mapEncryptedTypeToOID() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("mapEncryptedTypeToOID() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
