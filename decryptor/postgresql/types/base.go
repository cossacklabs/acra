package types

import (
	"context"
	"fmt"

	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	"github.com/cossacklabs/acra/encryptor/config/common"
	"github.com/sirupsen/logrus"
)

// EncodeDefault returns wrapped default value from settings ready for encoding
// returns nil if something went wrong, which in many cases indicates that the
// original value should be returned as it is
func EncodeDefault(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	strValue := format.GetDefaultDataValue()
	if strValue == nil {
		logrus.Errorln("Default value is not specified")
		return ctx, nil, nil
	}

	dataTypesEncoders := type_awareness.GetPostgreSQLDataTypeIDEncoders()
	dataTypeIDEncoder := dataTypesEncoders[format.GetDBDataTypeID()]

	return dataTypeIDEncoder.EncodeDefault(ctx, []byte(*strValue), format)
}

// EncodeOnFail returns either an error, which should be returned, or value, which
// should be encoded, because there is some problem with original, or `nil`
// which indicates that original value should be returned as is.
func EncodeOnFail(ctx context.Context, format type_awareness.DataTypeFormat) (context.Context, []byte, error) {
	action := format.GetResponseOnFail()
	switch action {
	case common.ResponseOnFailEmpty, common.ResponseOnFailCiphertext:
		return ctx, nil, nil

	case common.ResponseOnFailDefault:
		return EncodeDefault(ctx, format)

	case common.ResponseOnFailError:
		return nil, nil, base.NewEncodingError(format.GetColumnName())
	}

	return ctx, nil, fmt.Errorf("unknown action: %q", action)
}
