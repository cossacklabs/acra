package base

import (
	"fmt"
	"golang.org/x/net/context"
)

// EncodingError is returned from encoding handlers when some failure occurs.
// This error should be sent to the user directly, so it needs to be own type
// to be distinguishable.
type EncodingError struct {
	column string
}

func (e *EncodingError) Error() string {
	return fmt.Sprintf("encoding error in column %q", e.column)
}

// Is checks if err is the same as target error.
// It checks the type and the `.column` field.
// Used in tests to provide functionality of `errors.Is`
func (e *EncodingError) Is(err error) bool {
	encErr, ok := err.(*EncodingError)
	if !ok {
		return false
	}
	return encErr.column == e.column
}

// NewEncodingError returns new EncodingError with specified column
func NewEncodingError(column string) error {
	return &EncodingError{column}
}

// EncodingValue represents a (possibly parsed and prepared) value that is
// ready to be encoded
type EncodingValue interface {
	// AssBinary returns value encoded in a binary format
	AsBinary() []byte
	// AsText returns value encoded in a text format
	AsText() []byte
}

// EncodingValueFactory represents a factory that produces ready for encoding
// value.
type EncodingValueFactory interface {
	// NewStringValue creates a value that encodes as a str
	NewStringValue(str []byte) EncodingValue
	// NewBytesValue creates a value that encodes as bytes
	NewBytesValue(bytes []byte) EncodingValue
	// NewInt32Value creates a value that encodes as int32
	NewInt32Value(intVal int32, strVal []byte) EncodingValue
	// NewInt64Value creates a value that encodes as int64
	NewInt64Value(intVal int64, strVal []byte) EncodingValue
}

type decodedValueKey struct{}

// EncodedValueContext save encoded value in the context. Can be used to save encoded value before decoding from database
// to return as is on decryption failures
func EncodedValueContext(ctx context.Context, value []byte) context.Context {
	return context.WithValue(ctx, decodedValueKey{}, value)
}

// GetEncodedValueFromContext returns encoded value and true if it was saved, otherwise returns nil, false
func GetEncodedValueFromContext(ctx context.Context) ([]byte, bool) {
	value := ctx.Value(decodedValueKey{})
	if value == nil {
		return nil, false
	}
	val, ok := value.([]byte)
	if !ok {
		return nil, false
	}
	return val, true
}
