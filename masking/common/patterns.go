/*
 * Copyright 2020, Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"errors"
	"fmt"
	"github.com/cossacklabs/acra/encryptor/config/common"
)

// PlainTextSide defines which side of data is left untouched (in plain), and which is masked with a pattern.
type PlainTextSide string

// Allowable values for PlainTextSide
const (
	PlainTextSideLeft  PlainTextSide = "left"
	PlainTextSideRight PlainTextSide = "right"
)

// Validaton errors
var (
	ErrInvalidPlaintextLength = errors.New("plaintext length cannot be negative")
	ErrInvalidPlaintextSide   = errors.New("plaintext side must be left of right")
	ErrInvalidMaskingPattern  = errors.New("masking pattern can't be empty")
)

// ValidateMaskingParams checks and returns an error if masking parameters are incorrect.
func ValidateMaskingParams(pattern string, plaintextLength int, plaintextSide PlainTextSide, dataType common.EncryptedType) error {
	if len(pattern) == 0 {
		return ErrInvalidMaskingPattern
	}
	if plaintextLength < 0 {
		return ErrInvalidPlaintextLength
	}
	if plaintextSide != PlainTextSideRight && plaintextSide != PlainTextSideLeft {
		return ErrInvalidPlaintextSide
	}
	switch dataType {
	//case common2.EncryptedType_String, common2.EncryptedType_Bytes:
	case common.EncryptedType_String, common.EncryptedType_Bytes:
		break
	default:
		// intX not supported masking with type awareness
		return fmt.Errorf("masking configuration error: %w", common.ErrUnsupportedEncryptedType)
	}
	return nil
}
