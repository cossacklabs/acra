/*
 * Copyright 2021, Cossack Labs Limited
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

package config

import (
	"errors"
	"fmt"

	"github.com/cossacklabs/acra/decryptor/base/type_awareness"
	"github.com/cossacklabs/acra/encryptor/config/common"
	maskingCommon "github.com/cossacklabs/acra/masking/common"
	tokenizationCommon "github.com/cossacklabs/acra/pseudonymization/common"
	log "github.com/sirupsen/logrus"
)

// SettingMask bitmask used to store info about encryptor configuration
type SettingMask int32

// set of flags according to BasicColumnEncryptionSetting public fields except Name which is required
const (
	SettingReEncryptionFlag SettingMask = 1 << iota
	SettingMaskingFlag
	SettingMaskingPlaintextLengthFlag
	SettingMaskingPlaintextSideFlag
	SettingTokenizationFlag
	SettingConsistentTokenizationFlag
	SettingTokenTypeFlag
	SettingSearchFlag
	SettingClientIDFlag
	SettingZoneIDFlag
	SettingAcraBlockEncryptionFlag
	SettingAcraStructEncryptionFlag
	SettingDataTypeFlag
	SettingDefaultDataValueFlag
	SettingOnFailFlag
	SettingDataTypeIDFlag
)

// validSettings store all valid combinations of encryption settings
var validSettings = map[SettingMask]struct{}{
	// JUST ENCRYPTION
	// reencrypt to acrablock

	// ClientID
	SettingClientIDFlag | SettingAcraStructEncryptionFlag: {},
	SettingClientIDFlag | SettingAcraBlockEncryptionFlag:  {},

	SettingClientIDFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag: {},
	SettingClientIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:  {},
	// ZoneID
	SettingZoneIDFlag | SettingAcraBlockEncryptionFlag:  {},
	SettingZoneIDFlag | SettingAcraStructEncryptionFlag: {},

	SettingZoneIDFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},
	SettingZoneIDFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},

	/////////////
	// DataType tampering
	/////////////

	// AcraBlock

	// ClientID
	SettingDataTypeFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag:                                                   {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag:                               {},
	SettingDataTypeFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag:                     {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag: {},

	SettingDataTypeIDFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag:                                                   {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag:                               {},
	SettingDataTypeIDFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag:                     {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag: {},

	SettingDataTypeFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextLengthFlag | SettingMaskingPlaintextSideFlag:   {},
	SettingDataTypeIDFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextLengthFlag | SettingMaskingPlaintextSideFlag: {},

	// ZoneID

	SettingDataTypeFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag:                                                   {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag:                               {},
	SettingDataTypeFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag:                     {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag: {},

	SettingDataTypeIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag:                                                   {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag:                               {},
	SettingDataTypeIDFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag:                     {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag | SettingZoneIDFlag: {},

	// AcraStruct
	// ClientID
	SettingDataTypeFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag:                                                   {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag:                               {},
	SettingDataTypeFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag:                     {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag: {},

	SettingDataTypeIDFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag:                                                   {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag:                               {},
	SettingDataTypeIDFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag:                     {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag: {},

	// ZoneID

	SettingDataTypeFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag:                                                   {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag:                               {},
	SettingDataTypeFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag:                     {},
	SettingDataTypeFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag: {},

	SettingDataTypeIDFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag:                                                   {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag:                               {},
	SettingDataTypeIDFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag:                     {},
	SettingDataTypeIDFlag | SettingOnFailFlag | SettingDefaultDataValueFlag | SettingReEncryptionFlag | SettingAcraStructEncryptionFlag | SettingZoneIDFlag: {},

	/////////////
	// SEARCHABLE
	// default ClientID
	SettingSearchFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingSearchFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},
	// default ClientID with data type flag
	SettingDataTypeFlag | SettingSearchFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDataTypeFlag | SettingSearchFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	SettingDataTypeIDFlag | SettingSearchFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDataTypeIDFlag | SettingSearchFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	// default ClientID with data type default
	SettingDefaultDataValueFlag | SettingDataTypeFlag | SettingSearchFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDefaultDataValueFlag | SettingDataTypeFlag | SettingSearchFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	SettingDefaultDataValueFlag | SettingDataTypeIDFlag | SettingSearchFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDefaultDataValueFlag | SettingDataTypeIDFlag | SettingSearchFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	// specified ClientID
	SettingSearchFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingSearchFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},
	// specified ClientID with data type flag
	SettingDataTypeFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDataTypeFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	SettingDataTypeIDFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDataTypeIDFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	// specified ClientID with data type default
	SettingDefaultDataValueFlag | SettingDataTypeFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDefaultDataValueFlag | SettingDataTypeFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	SettingDefaultDataValueFlag | SettingDataTypeIDFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraStructEncryptionFlag | SettingReEncryptionFlag: {},
	SettingDefaultDataValueFlag | SettingDataTypeIDFlag | SettingSearchFlag | SettingClientIDFlag | SettingAcraBlockEncryptionFlag | SettingReEncryptionFlag:  {},

	/////////////
	// MASKING (should be specified all 3 parameters)
	// default ClientID
	SettingAcraStructEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextSideFlag | SettingMaskingPlaintextLengthFlag | SettingReEncryptionFlag: {},
	SettingAcraBlockEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextSideFlag | SettingMaskingPlaintextLengthFlag | SettingReEncryptionFlag:  {},
	// specified ClientID
	SettingAcraStructEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextSideFlag | SettingMaskingPlaintextLengthFlag | SettingClientIDFlag | SettingReEncryptionFlag: {},
	SettingAcraBlockEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextSideFlag | SettingMaskingPlaintextLengthFlag | SettingClientIDFlag | SettingReEncryptionFlag:  {},
	// specified ZoneID
	SettingAcraStructEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextSideFlag | SettingMaskingPlaintextLengthFlag | SettingZoneIDFlag | SettingReEncryptionFlag: {},
	SettingAcraBlockEncryptionFlag | SettingMaskingFlag | SettingMaskingPlaintextSideFlag | SettingMaskingPlaintextLengthFlag | SettingZoneIDFlag | SettingReEncryptionFlag:  {},

	/////////////
	// TOKENIZATION
	// default clientID
	SettingTokenizationFlag | SettingTokenTypeFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag: {},
	SettingTokenTypeFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                           {},

	SettingTokenizationFlag | SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingReEncryptionFlag:                                  {},
	SettingTokenizationFlag | SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag: {},
	SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingReEncryptionFlag:                                                            {},
	SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                           {},
	// specified clientID
	SettingTokenizationFlag | SettingTokenTypeFlag | SettingClientIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                                     {},
	SettingTokenizationFlag | SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingClientIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag: {},
	SettingTokenTypeFlag | SettingClientIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                                                               {},
	SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingClientIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                           {},
	// specified zoneID
	SettingTokenizationFlag | SettingTokenTypeFlag | SettingZoneIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                                     {},
	SettingTokenizationFlag | SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingZoneIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag: {},
	SettingTokenTypeFlag | SettingZoneIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                                                               {},
	SettingTokenTypeFlag | SettingConsistentTokenizationFlag | SettingZoneIDFlag | SettingReEncryptionFlag | SettingAcraBlockEncryptionFlag:                           {},
}

// Token type names as expected in the configuration file.
var tokenTypeNames = map[string]tokenizationCommon.TokenType{
	"int32": tokenizationCommon.TokenType_Int32,
	"int64": tokenizationCommon.TokenType_Int64,
	"str":   tokenizationCommon.TokenType_String,
	"bytes": tokenizationCommon.TokenType_Bytes,
	"email": tokenizationCommon.TokenType_Email,
}

// CryptoEnvelopeType type of crypto envelope for encryptors
type CryptoEnvelopeType string

// Supported CryptoEnvelopeTypes
const (
	CryptoEnvelopeTypeAcraStruct CryptoEnvelopeType = "acrastruct"
	CryptoEnvelopeTypeAcraBlock  CryptoEnvelopeType = "acrablock"
)

// ErrInvalidCryptoEnvelopeType used for invalid values of CryptoEnvelopeType
var ErrInvalidCryptoEnvelopeType = errors.New("invalid CryptoEnvelopeType")

// ErrInvalidEncryptorConfig has invalid configuration
var ErrInvalidEncryptorConfig = errors.New("invalid encryptor config")

// ValidateCryptoEnvelopeType return error if value is unsupported CryptoEnvelopeType
func ValidateCryptoEnvelopeType(value CryptoEnvelopeType) error {
	switch value {
	case CryptoEnvelopeTypeAcraStruct, CryptoEnvelopeTypeAcraBlock:
		return nil
	default:
		return ErrInvalidCryptoEnvelopeType
	}
}

// BasicColumnEncryptionSetting is a basic set of column encryption settings.
type BasicColumnEncryptionSetting struct {
	Name         string `yaml:"column"`
	UsedClientID string `yaml:"client_id"`
	UsedZoneID   string `yaml:"zone_id"`

	// same as TokenType but related for encryption operations
	DataType string `yaml:"data_type"`
	// same as DataType but expect exact ID type
	DataTypeID uint32 `yaml:"data_type_db_identifier"`
	// string for str/email/int32/int64 ans base64 string for binary data
	DefaultDataValue *string `yaml:"default_data_value"`
	// an action that should be performed on failure
	// possible actions are "ciphertext", "error" or "default"
	ResponseOnFail common.ResponseOnFail `yaml:"response_on_fail"`

	// Data pseudonymization (tokenization)

	// Tokenized is DEPRECATED, but left to provide backwards compatibility.
	// Was used to enable tokenization. Right now the `TokenType` serves that
	// purpose: if it's not empty, tokenization is enabled.
	Tokenized              *bool  `yaml:"tokenized"`
	ConsistentTokenization bool   `yaml:"consistent_tokenization"`
	TokenType              string `yaml:"token_type"`

	// Searchable encryption
	Searchable bool `yaml:"searchable"`
	// Data masking
	MaskingPattern           string                      `yaml:"masking"`
	PartialPlaintextLenBytes int                         `yaml:"plaintext_length"`
	PlaintextSide            maskingCommon.PlainTextSide `yaml:"plaintext_side"`
	CryptoEnvelope           *CryptoEnvelopeType         `yaml:"crypto_envelope"`
	ReEncryptToAcraBlock     *bool                       `yaml:"reencrypting_to_acrablocks"`
	settingMask              SettingMask
}

// IsBinaryDataOperation return true if setting related to operation over binary data
func IsBinaryDataOperation(setting ColumnEncryptionSetting) bool {
	// tokenization for binary data or encryption/masking of binary data (not text)
	hasBinaryOperation := setting.GetTokenType() == tokenizationCommon.TokenType_Bytes
	hasBinaryOperation = hasBinaryOperation || setting.OnlyEncryption() || setting.IsSearchable()
	hasBinaryOperation = hasBinaryOperation || len(setting.GetMaskingPattern()) != 0
	return hasBinaryOperation
}

// Init validate and initialize SettingMask
func (s *BasicColumnEncryptionSetting) Init(useMySQL bool) (err error) {
	if len(s.Name) == 0 {
		return ErrInvalidEncryptorConfig
	}

	s.settingMask = 0
	if len(s.ClientID()) > 0 {
		s.settingMask |= SettingClientIDFlag
	} else if len(s.ZoneID()) > 0 {
		s.settingMask |= SettingZoneIDFlag
	} else {
		// will be used default ClientID
		s.settingMask |= SettingClientIDFlag
	}
	if s.CryptoEnvelope != nil {
		if err = ValidateCryptoEnvelopeType(*s.CryptoEnvelope); err != nil {
			return err
		}
		switch *s.CryptoEnvelope {
		case CryptoEnvelopeTypeAcraStruct:
			s.settingMask |= SettingAcraStructEncryptionFlag
			break
		case CryptoEnvelopeTypeAcraBlock:
			s.settingMask |= SettingAcraBlockEncryptionFlag
			break
		}
	}
	if s.ReEncryptToAcraBlock != nil && *s.ReEncryptToAcraBlock {
		s.settingMask |= SettingReEncryptionFlag
	}

	if s.Tokenized != nil {
		tokenized := *s.Tokenized
		if tokenized && s.TokenType == "" {
			return errors.New("`tokenized` is provided without `token_type`")
		} else if !tokenized && s.TokenType != "" {
			return errors.New("`tokenized` is disabled, but `token_type` is provided")
		}
		log.Warnln("Setting `tokenized` flag is not necessary anymore and will be ignored")
	}

	var tokenType tokenizationCommon.TokenType
	var ok bool
	if s.TokenType != "" {
		tokenType, ok = tokenTypeNames[s.TokenType]
		if !ok {
			return fmt.Errorf("%s: %w", s.TokenType, tokenizationCommon.ErrUnknownTokenType)
		}
		if err = tokenizationCommon.ValidateTokenType(tokenType); err != nil {
			return err
		}
	}

	if s.ResponseOnFail != common.ResponseOnFailEmpty {
		s.settingMask |= SettingOnFailFlag
	} else if s.DefaultDataValue != nil {
		// if `response_on_fail` is not defined, but `default_data_value` is,
		// then we automatically set `response_on_fail` to default value
		// to simplify configuration for the user
		s.ResponseOnFail = common.ResponseOnFailDefault
	} else {
		// Otherwise, default action is to return ciphertext
		s.ResponseOnFail = common.ResponseOnFailCiphertext
	}

	if err := common.ValidateOnFail(s.ResponseOnFail); err != nil {
		return err
	}

	dataType := common.EncryptedType_Unknown
	if s.DataType == "" {
		// if DataType empty but configured for tokenization then map TokenType to appropriate DataType
		if s.TokenType != "" {
			s.DataType, err = common.TokenTypeToEncryptedDataType(tokenType).ToConfigString()
			if err != nil {
				return err
			}
		}
	} else {
		// set mask only if it set explicitly, not via token_type
		s.settingMask |= SettingDataTypeFlag
	}

	if s.DataType != "" {
		if s.DataTypeID != 0 {
			return common.ErrDataTypeWithDataTypeID
		}

		dataType, err = common.ParseStringEncryptedType(s.DataType)
		if err != nil {
			return fmt.Errorf("%s: %w", s.DataType, common.ErrUnknownEncryptedType)
		}
		if err = common.ValidateEncryptedType(dataType); err != nil {
			return err
		}
	}

	if s.DataTypeID != 0 {
		s.settingMask |= SettingDataTypeIDFlag

		var dataTypeIDEncoders = type_awareness.GetPostgreSQLDataTypeIDEncoders()
		if useMySQL {
			//dataTypeIDEncoders = base.GetMySQLDataTypeIDEncoders()
		}

		_, ok := dataTypeIDEncoders[s.DataTypeID]
		if !ok {
			return fmt.Errorf("%d: %w", s.DataTypeID, common.ErrUnsupportedDBDataTypeID)
		}

		if useMySQL {
			//s.DataType = base.MySQLEncryptedTypeDataTypeIDs[dataType]
		} else {
			s.DataType = common.PostgreSQLDataTypeIDEncryptedType[s.DataTypeID]
		}
		dataType, _ = common.ParseStringEncryptedType(s.DataType)
	}

	if s.DataTypeID == 0 && s.DataType != "" {
		if useMySQL {
			//s.DataTypeID = base.MySQLEncryptedTypeDataTypeIDs[dataType]
		} else {
			s.DataTypeID = common.PostgreSQLEncryptedTypeDataTypeIDs[dataType]
		}
	}

	if s.DefaultDataValue != nil {
		if dataType == common.EncryptedType_Unknown {
			return errors.New("default_data_value used without data_type")
		}
		s.settingMask |= SettingDefaultDataValueFlag
		if s.ResponseOnFail != common.ResponseOnFailDefault {
			return fmt.Errorf("default data value is defined, but `response_on_fail` operation is not \"default\" (%s)", s.ResponseOnFail)
		}
	}
	if err = common.ValidateDefaultValue(s.DefaultDataValue, dataType); err != nil {
		return fmt.Errorf("invalid default value: %w", err)
	}

	if s.TokenType != "" {
		s.settingMask |= SettingTokenizationFlag
		s.settingMask |= SettingTokenTypeFlag
		if s.ConsistentTokenization {
			s.settingMask |= SettingConsistentTokenizationFlag
		}
		// due to tokenization supports only AcraBlock and for backward compatibility, we reconfigure CryptoEnvelope always for AcraBlock
		// to leave Defaults support
		s.settingMask &= ^SettingAcraStructEncryptionFlag
		s.settingMask |= SettingAcraBlockEncryptionFlag
	}

	if s.MaskingPattern != "" || s.PlaintextSide != "" {
		if err = maskingCommon.ValidateMaskingParams(s.MaskingPattern, s.PartialPlaintextLenBytes, s.PlaintextSide, s.GetEncryptedDataType()); err != nil {
			return err
		}
		s.settingMask |= SettingMaskingFlag | SettingMaskingPlaintextLengthFlag | SettingMaskingPlaintextSideFlag
	}
	if s.Searchable {
		s.settingMask |= SettingSearchFlag
	}
	_, ok = validSettings[s.settingMask]
	if !ok {
		return ErrInvalidEncryptorConfig
	}
	return nil
}

// OnlyEncryption return true if should be applied only AcraStruct/AcraBlock encryption without tokenization/masking/etc
func (s *BasicColumnEncryptionSetting) OnlyEncryption() bool {
	return s.settingMask&(SettingMaskingFlag|SettingTokenizationFlag|SettingSearchFlag) == 0
}

// GetSettingMask return SettingMask
func (s *BasicColumnEncryptionSetting) GetSettingMask() SettingMask {
	return s.settingMask
}

// ColumnName returns name of the column for which these settings are for.
func (s *BasicColumnEncryptionSetting) ColumnName() string {
	return s.Name
}

// GetCryptoEnvelope returns type of crypto envelope
func (s *BasicColumnEncryptionSetting) GetCryptoEnvelope() CryptoEnvelopeType {
	if s.CryptoEnvelope == nil {
		return CryptoEnvelopeTypeAcraStruct
	}
	return *s.CryptoEnvelope
}

// ShouldReEncryptAcraStructToAcraBlock return true if should  re-encrypt data with AcraBlock
func (s *BasicColumnEncryptionSetting) ShouldReEncryptAcraStructToAcraBlock() bool {
	if s.ReEncryptToAcraBlock == nil {
		return false
	}
	return *s.ReEncryptToAcraBlock
}

// ClientID returns client ID to use when encrypting this column.
func (s *BasicColumnEncryptionSetting) ClientID() []byte {
	return []byte(s.UsedClientID)
}

// ZoneID returns zone ID to use when encrypting this column.
func (s *BasicColumnEncryptionSetting) ZoneID() []byte {
	return []byte(s.UsedZoneID)
}

// IsTokenized returns true if the column should be tokenized.
func (s *BasicColumnEncryptionSetting) IsTokenized() bool {
	return s.TokenType != ""
}

// IsConsistentTokenization returns true if column tokens should be consistent.
func (s *BasicColumnEncryptionSetting) IsConsistentTokenization() bool {
	return s.ConsistentTokenization
}

// GetTokenType return the type of tokenization to apply to the column.
func (s *BasicColumnEncryptionSetting) GetTokenType() tokenizationCommon.TokenType {
	// If the configuration file contains some unknown or unsupported token type,
	// return some safe default.
	const defaultTokenType = tokenizationCommon.TokenType_Unknown
	tokenType, ok := tokenTypeNames[s.TokenType]
	if !ok {
		return defaultTokenType
	}
	return tokenizationCommon.NormalizeTokenType(tokenType, defaultTokenType)
}

// IsSearchable returns true if column should be searchable.
func (s *BasicColumnEncryptionSetting) IsSearchable() bool {
	return s.Searchable
}

// GetMaskingPattern returns string which should be used to mask AcraStruct data.
func (s *BasicColumnEncryptionSetting) GetMaskingPattern() string {
	return s.MaskingPattern
}

// GetPartialPlaintextLen returns number of bytes to be left untouched in masked value.
func (s *BasicColumnEncryptionSetting) GetPartialPlaintextLen() int {
	return s.PartialPlaintextLenBytes
}

// IsEndMasking returns true if the right part of the value should be masked.
func (s *BasicColumnEncryptionSetting) IsEndMasking() bool {
	return s.PlaintextSide == maskingCommon.PlainTextSideLeft
}

// GetEncryptedDataType returns data type for encrypted data
func (s *BasicColumnEncryptionSetting) GetEncryptedDataType() common.EncryptedType {
	// If the configuration file contains some unknown or unsupported token type,
	// return some safe default.
	const defaultDataType = common.EncryptedType_Unknown
	dataType, err := common.ParseStringEncryptedType(s.DataType)
	if err != nil {
		return defaultDataType
	}
	return dataType
}

// GetDefaultDataValue returns default data value for encrypted data
func (s *BasicColumnEncryptionSetting) GetDefaultDataValue() *string {
	return s.DefaultDataValue
}

func (s *BasicColumnEncryptionSetting) applyDefaults(defaults defaultValues) {
	if s.CryptoEnvelope == nil {
		v := defaults.GetCryptoEnvelope()
		// not applicable to masking, tokenization and searchable encryption
		if s.settingMask&(SettingTokenizationFlag|SettingMaskingFlag) == 0 {
			s.CryptoEnvelope = &v
		}
	}
	if s.ReEncryptToAcraBlock == nil {
		v := defaults.ShouldReEncryptAcraStructToAcraBlock()
		// not applicable to masking, tokenization and searchable encryption
		if s.settingMask&(SettingTokenizationFlag|SettingMaskingFlag) == 0 {
			s.ReEncryptToAcraBlock = &v
		}
	}
}

// GetResponseOnFail returns the action that should be performed on failure
// Valid values are "", "ciphertext", "error" and "default"
func (s *BasicColumnEncryptionSetting) GetResponseOnFail() common.ResponseOnFail {
	return s.ResponseOnFail
}

// HasTypeAwareSupport return true if setting configured for decryption with type awareness
func HasTypeAwareSupport(setting ColumnEncryptionSetting) bool {
	maskingSupport := setting.GetMaskingPattern() != ""
	switch setting.GetEncryptedDataType() {
	case common.EncryptedType_String, common.EncryptedType_Bytes, common.EncryptedType_Int32, common.EncryptedType_Int64:
		break
	default:
		// intX not supported masking with type awareness
		maskingSupport = false
	}
	return setting.OnlyEncryption() || setting.IsSearchable() || maskingSupport
}

// GetDBDataTypeID returns the DataTypeID of corresponded DB got from `data_type_db_identifier` encryptor config option
func (s *BasicColumnEncryptionSetting) GetDBDataTypeID() uint32 {
	return s.DataTypeID
}
