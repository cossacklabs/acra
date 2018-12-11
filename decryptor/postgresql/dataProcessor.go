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

package postgresql

import (
	"encoding/hex"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/utils"
)

// NewEncodeDecodeWrapper encode/decode data to/from escaped format (hex/octal)
func NewEncodeDecodeWrapper(processor base.DataProcessor) base.DataProcessor {
	return base.ProcessorFunc(func(data []byte, ctx *base.DataProcessorContext) ([]byte, error) {
		data, err := utils.DecodeEscaped(data)
		if err != nil {
			return data, err
		}
		data, err = processor.Process(data, ctx)
		if err != nil {
			return data, err
		}
		output := make([]byte, len(HexPrefix)+hex.EncodedLen(len(data)))
		copy(output, HexPrefix)
		hex.Encode(output[len(HexPrefix):], data)
		return output, nil
	})
}
