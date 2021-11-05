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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"sort"
	"strings"
)

// LogParser is a common interface for parsers that are used for processing raw log entries
// that are passed as strings
type LogParser interface {
	// ParseEntry is called for extracting information from log entry string (with concrete format)
	ParseEntry(logEntry string) (*ParsedLogEntry, error)
}

// NewLogParser return LogParser according to format
func NewLogParser(format string) (LogParser, error) {
	switch strings.ToLower(format) {
	case CefFormatString:
		return &CefLogParser{}, nil
	case PlaintextFormatString:
		return &PlaintextLogParser{}, nil
	case JSONFormatString:
		return &JSONLogParser{}, nil
	default:
		return nil, ErrUnexpectedFormat
	}
}

// CefLogParser struct used as LogParser implementation for cef format
type CefLogParser struct{}

// JSONLogParser struct used as LogParser implementation for json format
type JSONLogParser struct{}

// PlaintextLogParser struct used as LogParser implementation for plaintext format
type PlaintextLogParser struct{}

// ParsedLogEntry struct store log data and related integrity metadata
type ParsedLogEntry struct {
	RawData    []byte
	Integrity  []byte
	IsNewChain bool
	IsEndChain bool
}

// Set of constants used internally by logging package
const (
	IntegrityKey              = "integrity"
	AuditLogChainKey          = "chain"
	NewAuditLogChainValue     = "new"
	EndAuditLogChainValue     = "end"
	JSONKeyValueDelimiter     = "delimiter"
	SpaceDelimiter            = " "
	EquallyDelimiter          = "="
	NewAuditLogChainSuffix    = "chain=new"
	EndOfAuditLogChainSuffix  = "chain=end"
	DataSplitToken            = SpaceDelimiter + IntegrityKey + EquallyDelimiter
	EndOfAuditLogChainMessage = "End of current audit log chain"
)

// ParseEntry parse cef log line with next expected input example and return ParsedLogEntry:
// CEF:0|<value>|<value>|<value>|100|<value>|1|unixTime=<value> integrity=<value> chain=<value>
// CEF:0|<value>|<value>|<value>|100|<value>|1|unixTime=<value> integrity=<value>
func (parser *CefLogParser) ParseEntry(rawData string) (*ParsedLogEntry, error) {
	parsedLogEntry := &ParsedLogEntry{}
	rawLogEntry := strings.Split(rawData, DataSplitToken)
	if len(rawLogEntry) != 2 {
		return nil, ErrCefIntegrityExtract
	}
	parsedLogEntry.RawData = []byte(rawLogEntry[0])
	// we need to trim additional space provided by cef
	rawLogEntry[1] = strings.TrimSpace(rawLogEntry[1])
	// check chain=new
	if strings.HasSuffix(rawLogEntry[1], SpaceDelimiter+NewAuditLogChainSuffix) {
		parsedLogEntry.IsNewChain = true
		rawLogEntry[1] = strings.TrimSuffix(rawLogEntry[1], SpaceDelimiter+NewAuditLogChainSuffix)
	}
	// handle chain=end case (check additionally that message is expected)
	if strings.Contains(rawLogEntry[0], EndOfAuditLogChainSuffix) {
		if strings.Contains(rawLogEntry[0], EndOfAuditLogChainMessage) {
			parsedLogEntry.IsEndChain = true
		}
	}
	integrity, err := hex.DecodeString(rawLogEntry[1])
	if err != nil {
		return nil, fmt.Errorf("[cef] can't parse integrity: %w", err)
	}
	parsedLogEntry.Integrity = integrity
	return parsedLogEntry, nil
}

// ParseEntry parse plaintext log line with next expected input example and return ParsedLogEntry:
// time="<value>" level=<value> msg="<value>" version=<value> integrity=<value> chain=<value>
// time="<value>" level=<value> msg="<value>" version=<value> integrity=<value>
func (parser *PlaintextLogParser) ParseEntry(rawData string) (*ParsedLogEntry, error) {
	parsedLogEntry := &ParsedLogEntry{}
	rawLogEntry := strings.Split(rawData, DataSplitToken)
	if len(rawLogEntry) != 2 {
		return nil, ErrPlaintextIntegrityExtract
	}
	parsedLogEntry.RawData = []byte(rawLogEntry[0])
	// handle chain=new
	if strings.HasSuffix(rawLogEntry[1], SpaceDelimiter+NewAuditLogChainSuffix) {
		parsedLogEntry.IsNewChain = true
		rawLogEntry[1] = strings.TrimSuffix(rawLogEntry[1], SpaceDelimiter+NewAuditLogChainSuffix)
	}
	// handle chain=end case (check additionally that message is expected)
	if strings.Contains(rawLogEntry[0], EndOfAuditLogChainSuffix) {
		if strings.Contains(rawLogEntry[0], EndOfAuditLogChainMessage) {
			parsedLogEntry.IsEndChain = true
		}
	}

	integrity, err := hex.DecodeString(rawLogEntry[1])
	if err != nil {
		return nil, fmt.Errorf("[plaintext] can't parse integrity: %w", err)
	}
	parsedLogEntry.Integrity = integrity
	return parsedLogEntry, nil
}

// ParseEntry parse json log line with next expected input example and return ParsedLogEntry:
// {"chain": "<val>","integrity":"<val>", "level":"<val>","msg":"<val>","product":"<val>","timestamp":"<val>","unixTime":"<val>","version":"<val>"}
// {"integrity":"<val>", "level":"<val>","msg":"<val>","product":"<val>","timestamp":"<val>","unixTime":"<val>","version":"<val>"}
func (parser *JSONLogParser) ParseEntry(rawData string) (*ParsedLogEntry, error) {
	parsed := make(map[string]interface{})
	logEntry := &ParsedLogEntry{}
	err := json.Unmarshal([]byte(rawData), &parsed)
	if err != nil {
		return nil, fmt.Errorf("[json] can't parse integrity: %w", err)
	}
	integrityString, ok := parsed[IntegrityKey].(string)
	if !ok {
		return nil, ErrJSONIntegrityExtract
	}
	integrity, err := hex.DecodeString(integrityString)
	if err != nil {
		return nil, fmt.Errorf("[json] can't parse integrity: %w", err)
	}
	delete(parsed, IntegrityKey)
	logEntry.Integrity = integrity
	chainValue, ok := parsed[AuditLogChainKey].(string)
	if ok {
		if chainValue == NewAuditLogChainValue {
			// handle "chain":"new" case
			logEntry.IsNewChain = true
			delete(parsed, AuditLogChainKey)

		} else if chainValue == EndAuditLogChainValue {
			// handle "chain":"end" case (check additionally that message is expected)
			expectedMessage, ok := parsed[logrus.FieldKeyMsg].(string)
			if ok && expectedMessage == EndOfAuditLogChainMessage {
				logEntry.IsEndChain = true
			}
			// in this case we do not remove chain key/value from parsed log entry since it is cryptographically bounded
		}
	}
	entryData, err := convertMapToBytes(parsed)
	if err != nil {
		return nil, err
	}
	logEntry.RawData = entryData
	return logEntry, nil
}

func convertMapToBytes(parsed map[string]interface{}) ([]byte, error) {
	var keys []string
	for k := range parsed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rawDataBytes []byte
	for _, key := range keys {
		keyBytes := []byte(key)
		rawDataBytes = append(rawDataBytes, []byte(JSONKeyValueDelimiter)...)
		rawDataBytes = append(rawDataBytes, keyBytes...)
		rawDataBytes = append(rawDataBytes, []byte(JSONKeyValueDelimiter)...)
		valueBytes, err := getBytes(parsed[key])
		if err != nil {
			return nil, err
		}
		rawDataBytes = append(rawDataBytes, valueBytes...)
		rawDataBytes = append(rawDataBytes, []byte(JSONKeyValueDelimiter)...)
	}
	return rawDataBytes, nil
}

func getBytes(key interface{}) ([]byte, error) {
	// TODO serialization (storojs72, 19.03.2020)
	// This is questionable way of type serialization to bytes.
	// We will need to find a common and consistent way of serialization in future
	// https://ph.cossacklabs.com/T1560
	return json.Marshal(key)
}
