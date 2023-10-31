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

package base

import (
	"errors"

	"github.com/cossacklabs/acra/encryptor/base/config"
	"github.com/cossacklabs/acra/sqlparser"
)

// errUnsupportedExpression unsupported type of literal to binary encode/decode
var ErrUnsupportedExpression = errors.New("unsupported expression")

// DBDataCoder encode/decode binary data to correct string form for specific db
type DBDataCoder interface {
	Decode(sqlparser.Expr, config.ColumnEncryptionSetting) ([]byte, error)
	Encode(sqlparser.Expr, []byte, config.ColumnEncryptionSetting) ([]byte, error)
}
