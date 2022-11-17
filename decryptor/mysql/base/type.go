package base

// Type used for defining MySQL types
type Type byte

// StorageByte represent amount of bytes need to store MySQL type
type StorageByte int

// NumericTypesStorageBytes return association between numeric types and amount of bytes used for their storing
var NumericTypesStorageBytes = map[Type]StorageByte{
	TypeTiny:     StorageByte(1),
	TypeShort:    StorageByte(2),
	TypeYear:     StorageByte(2),
	TypeLong:     StorageByte(4),
	TypeFloat:    StorageByte(4),
	TypeInt24:    StorageByte(4),
	TypeDouble:   StorageByte(8),
	TypeLongLong: StorageByte(8),
	TypeNull:     StorageByte(0),
}

// Bits return number of bits of the StorageByte
func (s StorageByte) Bits() int {
	return int(s) * 8
}

// IsBinaryType true if field type is binary
func (t Type) IsBinaryType() bool {
	isBlob := t >= TypeTinyBlob && t <= TypeBlob
	isString := t == TypeVarString || t == TypeString
	return isString || isBlob || t == TypeVarchar
}

// Binary ColumnTypes https://dev.mysql.com/doc/dev/mysql-server/latest/namespaceclassic__protocol_1_1field__type.html
const (
	TypeDecimal Type = iota
	TypeTiny
	TypeShort
	TypeLong
	TypeFloat
	TypeDouble
	TypeNull
	TypeTimestamp
	TypeLongLong
	TypeInt24
	TypeDate
	TypeTime
	TypeDatetime
	TypeYear
	TypeNewDate
	TypeVarchar
	TypeBit
)

// MySQL types
const (
	TypeNewDecimal Type = iota + 0xf6
	TypeEnum
	TypeSet
	TypeTinyBlob
	TypeMediumBlob
	TypeLongBlob
	TypeBlob
	TypeVarString
	TypeString
	TypeGeometry
)
