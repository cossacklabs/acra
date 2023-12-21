package base

import "github.com/cossacklabs/acra/encryptor/base/config"

// BoundValue is a value provided for prepared statement execution.
// Its exact type and meaning depends on the corresponding query.
type BoundValue interface {
	Format() BoundValueFormat
	Copy() BoundValue
	SetData(newData []byte, setting config.ColumnEncryptionSetting) error
	GetData(setting config.ColumnEncryptionSetting) ([]byte, error)
	Encode() ([]byte, error)
	GetType() byte
}

// BoundValueFormat specifies how to interpret the bound data.
type BoundValueFormat uint16

// Supported values of BoundValueFormat.
const (
	TextFormat BoundValueFormat = iota
	BinaryFormat
)
