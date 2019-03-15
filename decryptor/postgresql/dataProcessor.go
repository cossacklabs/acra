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
	"github.com/sirupsen/logrus"
)

// NewEncodeDecodeWrapper encode/decode data to/from escaped format (hex/octal)
func NewEncodeDecodeWrapper(processor base.DataProcessor) base.DataProcessor {
	return base.ProcessorFunc(func(data []byte, ctx *base.DataProcessorContext) ([]byte, error) {
		decodedData, err := utils.DecodeEscaped(data)
		if err != nil {
			logrus.WithError(err).Debugln("Data is not in hex/escape format, process as binary data (used in prepared statements)")
			decodedData = data
		}
		data, err = processor.Process(decodedData, ctx)
		if err != nil {
			return data, err
		}

		// if data was simple string without binary data then return it as is otherwise encode as hex value
		for _, c := range data {
			if !utils.IsPrintableEscapeChar(c) {
				output := make([]byte, len(HexPrefix)+hex.EncodedLen(len(data)))
				copy(output, HexPrefix)
				hex.Encode(output[len(HexPrefix):], data)
				data = output
				break
			}
		}
		return data, nil
	})
}
