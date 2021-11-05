/*
Copyright 2020, Cossack Labs Limited

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

package logging

import (
	"crypto/subtle"
	"errors"
	log "github.com/sirupsen/logrus"
	"os"
)

// IntegrityCheckVerifier implement audit log verification
type IntegrityCheckVerifier struct {
	cryptoKey           []byte
	integrityCalculator *LogEntryIntegrityCalculator
	parser              LogParser
	lastVerifiedEntry   *ParsedLogEntry
}

// NewIntegrityCheckVerifier return new IntegrityCheckVerifier with configure secret key and parser
func NewIntegrityCheckVerifier(key []byte, parser LogParser) (*IntegrityCheckVerifier, error) {
	return &IntegrityCheckVerifier{
		cryptoKey:           key,
		integrityCalculator: NewLogEntryIntegrityCalculator(key),
		parser:              parser,
	}, nil
}

// LogEntryInfo consists from raw log entry and metadata
type LogEntryInfo struct {
	RawLogEntry string
	FileInfo    os.FileInfo
	LineNumber  int
}

// LogEntrySource is a stream of log entries for verification. When Entries is exhausted, look into Error to check
// if an error occurred
type LogEntrySource struct {
	Entries <-chan *LogEntryInfo
	Error   error
}

// VerifyIntegrityCheck verify all lines incoming to channel (which is a part of input log entry source)
// until it will be closed and return (nil, nil) if fully verified, otherwise return current log entry with error occurred
func (v *IntegrityCheckVerifier) VerifyIntegrityCheck(source *LogEntrySource) (*LogEntryInfo, error) {
	for logEntry := range source.Entries {
		if logEntry == nil {
			return nil, errors.New("got unexpected nil logEntry on verification")
		}
		// skip empty strings that may come as log entries
		if logEntry.RawLogEntry == "" {
			continue
		}
		parsedLogEntry, err := v.parser.ParseEntry(logEntry.RawLogEntry)
		if err != nil {
			if err == ErrCefIntegrityExtract || err == ErrPlaintextIntegrityExtract || err == ErrJSONIntegrityExtract {
				log.Warningln("No integrity check for line: ", logEntry.LineNumber+1)
				continue
			} else {
				return logEntry, err
			}
		}
		if parsedLogEntry.IsNewChain {
			if v.lastVerifiedEntry != nil {
				if !v.lastVerifiedEntry.IsEndChain {
					return logEntry, ErrMissingEndOfChain
				}
			}
			v.integrityCalculator.ResetCryptoKey(v.cryptoKey)
		}

		calculated, _, err := v.integrityCalculator.CalculateIntegrityCheck(parsedLogEntry.RawData)
		if err != nil {
			return logEntry, err
		}
		if subtle.ConstantTimeCompare(parsedLogEntry.Integrity, calculated) == 0 {
			return logEntry, ErrIntegrityNotMatch
		}
		// save current entry
		v.lastVerifiedEntry = parsedLogEntry
	}
	// forward error that may occur while reading log entry from file
	if source.Error != nil {
		return nil, source.Error
	}
	// additional check of valid end for last chain
	if v.lastVerifiedEntry == nil {
		log.Warningln("Empty source of audit log")
		return nil, nil
	}
	if !v.lastVerifiedEntry.IsEndChain {
		log.Warningln("Missing end of final audit log chain")
	}
	// successful case
	return nil, nil
}
