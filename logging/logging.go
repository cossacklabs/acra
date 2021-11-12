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

// Package logging contains custom log formatters (plaintext, JSON and CEF) to use through Acra components.
// Logging mode and verbosity level can be configured for AcraServer, AcraConnector in the
// corresponding yaml files or passed as CLI parameter.
//
// https://github.com/cossacklabs/acra/wiki/Logging
package logging

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Log modes
const (
	LogDebug = iota
	LogVerbose
	LogDiscard
)

// Log formats
const (
	PlaintextFormatString = "plaintext"
	JSONFormatString      = "json"
	CefFormatString       = "cef"
)

// LoggerSetter abstract types that provide way to set logger which they should use
type LoggerSetter interface {
	SetLogger(*log.Entry)
}

// FormatterHook provides post-processing customization to log formatters,
// allowing you to execute additional code before or after an entry is completed.
type FormatterHook interface {
	// PreFormat is called before the entry is serialized by the formatter.
	// You may inspect as well as add or remove fields of the log entry.
	// If the error is not nil, formatting fails with returned error.
	PreFormat(entry *log.Entry) error
	// PostFormat is called after the entry has been serialized by the formatter.
	// You may inspect log entry fields and the byte buffer with serialized data.
	// You may also modify the resulting buffer with serialized entry.
	// If the error is not nil, formatting fails with returned error.
	PostFormat(entry *log.Entry, formatted *bytes.Buffer) error
}

type loggerKey struct{}

// IsDebugLevel return true if logger configured to log debug messages
func IsDebugLevel(logger *log.Entry) bool {
	return logger.Level == log.DebugLevel
}

// Formatter wraps log.Formatter interface and adds functions for customizations.
// Intention for this interface is to provide ability to customize logging by accustomed:
// `SetServiceName` / `SetHooks` from main function of Acra services
type Formatter interface {
	log.Formatter
	SetServiceName(serviceName string)
	SetHooks(hooks []FormatterHook)
	GetHooks() []FormatterHook
}

// SetLogLevel sets logging level
func SetLogLevel(level int) {
	if level == LogDebug {
		log.SetLevel(log.DebugLevel)
	} else if level == LogVerbose {
		log.SetLevel(log.InfoLevel)
	} else if level == LogDiscard {
		log.SetLevel(log.WarnLevel)
	} else {
		panic(fmt.Sprintf("Incorrect log level - %v", level))
	}
}

// CreateFormatter creates formatter object
func CreateFormatter(format string) Formatter {
	var formatter Formatter
	switch strings.ToLower(format) {
	case JSONFormatString:
		formatter = JSONFormatter()
	case CefFormatString:
		formatter = CEFFormatter()
	default:
		formatter = TextFormatter()
	}
	log.SetFormatter(formatter)
	return formatter
}

// GetLogLevel gets logrus log level and returns int Acra log level
func GetLogLevel() int {
	if log.GetLevel() == log.DebugLevel {
		return LogDebug
	}
	if log.GetLevel() == log.InfoLevel {
		return LogVerbose
	}
	return LogDiscard
}

// SetLoggerToContext sets logger to corresponded context
func SetLoggerToContext(ctx context.Context, logger *log.Entry) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// GetLoggerFromContext gets logger from context, returns nil if no logger.
func GetLoggerFromContext(ctx context.Context) *log.Entry {
	if entry, ok := GetLoggerFromContextOk(ctx); ok {
		return entry
	}
	return log.NewEntry(log.StandardLogger())
}

// GetLoggerFromContextOk gets logger from context, returns logger and success code.
func GetLoggerFromContextOk(ctx context.Context) (*log.Entry, bool) {
	entry, ok := ctx.Value(loggerKey{}).(*log.Entry)
	return entry, ok
}

var logToConsole bool
var logToFile string

// RegisterCLIArgs register cli args with flag used to configure logging
func RegisterCLIArgs() {
	flag.BoolVar(&logToConsole, "log_to_console", true, "Log to stderr if true")
	flag.StringVar(&logToFile, "log_to_file", "", "Log to file if pass not empty value")
}

// Set of error values related to enterprise logging
var (
	ErrUnexpectedFormat          = errors.New("unexpected log entry format")
	ErrIntegrityNotMatch         = errors.New("integrity doesn't match")
	ErrPlaintextIntegrityExtract = errors.New("[plaintext] can't extract integrity part")
	ErrCefIntegrityExtract       = errors.New("[cef] can't extract integrity part")
	ErrJSONIntegrityExtract      = errors.New("[json] can't extract integrity part")
	ErrMissingEndOfChain         = errors.New("end of audit log chain is missing")
)

// NewWriter creates writer that outputs logs into stdout and also into file if necessary
func NewWriter() (io.Writer, func(), error) {
	var writer []io.Writer
	if logToConsole {
		writer = append(writer, os.Stderr)
	}
	onClose := func() {}
	if logToFile != "" {
		f, err := os.OpenFile(logToFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, nil, err
		}
		writer = append(writer, f)
		onClose = func() {
			if err := f.Close(); err != nil {
				log.WithError(err).Errorln("Can't close log file")
			}
		}
	}
	return io.MultiWriter(writer...), onClose, nil
}

// NewHooks creates a set of formatter hooks with single "crypto" hook used by audit log functionality
func NewHooks(key []byte, loggingFormat string) ([]FormatterHook, error) {
	var hook FormatterHook
	var err error
	switch strings.ToLower(loggingFormat) {
	case JSONFormatString:
		hook, err = NewJSONFormatterHook(key)
	case CefFormatString:
		hook, err = NewCefFormatterHook(key)
	case PlaintextFormatString:
		hook, err = NewPlaintextFormatterHook(key)
	default:
		return nil, ErrUnexpectedFormat
	}
	if err != nil {
		return nil, err
	}
	return []FormatterHook{hook}, nil
}

// JSONFormatterHook struct to provide audit_log with json formatter
type JSONFormatterHook struct {
	integrityCalculator *LogEntryIntegrityCalculator
}

// CefFormatterHook struct to provide audit_log with cef formatter
type CefFormatterHook struct {
	integrityCalculator *LogEntryIntegrityCalculator
}

// PlaintextFormatterHook struct to provide audit_log with plaintext formatter
type PlaintextFormatterHook struct {
	integrityCalculator *LogEntryIntegrityCalculator
}

// NewJSONFormatterHook create new hook with json formatter support to provide audit_log
func NewJSONFormatterHook(key []byte) (*JSONFormatterHook, error) {
	return &JSONFormatterHook{
		integrityCalculator: NewLogEntryIntegrityCalculator(key),
	}, nil
}

// NewCefFormatterHook create new hook with cef formatter support to provide audit_log
func NewCefFormatterHook(key []byte) (*CefFormatterHook, error) {
	return &CefFormatterHook{
		integrityCalculator: NewLogEntryIntegrityCalculator(key),
	}, nil
}

// NewPlaintextFormatterHook create new hook with plaintext formatter support  to provide audit_log
func NewPlaintextFormatterHook(key []byte) (*PlaintextFormatterHook, error) {
	return &PlaintextFormatterHook{
		integrityCalculator: NewLogEntryIntegrityCalculator(key),
	}, nil
}

// PreFormat handler adds (if necessary) "end of chain" marker to the entry in order
// to cryptographically bound it to the integrity computation
func (h *JSONFormatterHook) PreFormat(entry *log.Entry) error {
	// we add EndOfChain marker into entry in pre-format stage because it should be cryptographically bounded to the log entry
	if strings.EqualFold(entry.Message, EndOfAuditLogChainMessage) {
		entry.Data[AuditLogChainKey] = EndAuditLogChainValue
	}
	return nil
}

// PostFormat handler adds integrity to output
func (h *JSONFormatterHook) PostFormat(entry *log.Entry, formatted *bytes.Buffer) error {
	parsed := make(map[string]interface{})
	err := json.Unmarshal(formatted.Bytes(), &parsed)
	if err != nil {
		return err
	}
	logEntryDataBytes, err := convertMapToBytes(parsed)
	if err != nil {
		return err
	}
	integrity, newChain, err := h.integrityCalculator.CalculateIntegrityCheck(logEntryDataBytes)
	if err != nil {
		return err
	}
	parsed[IntegrityKey] = hex.EncodeToString(integrity)
	if newChain {
		parsed[AuditLogChainKey] = NewAuditLogChainValue
	}
	newFormatted, err := json.Marshal(parsed)
	if err != nil {
		return err
	}
	formatted.Truncate(0)
	formatted.Write(newFormatted)
	formatted.WriteString("\n")
	return nil
}

// SetCryptoKey sets crypto key of this crypto hook
func (h *JSONFormatterHook) SetCryptoKey(key []byte) error {
	h.integrityCalculator.ResetCryptoKey(key)
	return nil
}

// PreFormat handler adds (if necessary) "end of chain" marker to the entry in order
// to cryptographically bound it to the integrity computation
func (h *CefFormatterHook) PreFormat(entry *log.Entry) error {
	if entry.Message == EndOfAuditLogChainMessage {
		entry.Data[AuditLogChainKey] = EndAuditLogChainValue
	}
	return nil
}

// SetCryptoKey sets crypto key of this crypto hook
func (h *CefFormatterHook) SetCryptoKey(key []byte) error {
	h.integrityCalculator.ResetCryptoKey(key)
	return nil
}

// PostFormat handler adds integrity to output
func (h *CefFormatterHook) PostFormat(entry *log.Entry, formatted *bytes.Buffer) error {
	// truncate `\n` and additional space symbol added by CEF formatter
	formatted.Truncate(formatted.Len() - 2)
	err := appendIntegrity(h.integrityCalculator, formatted)
	if err != nil {
		return err
	}
	formatted.WriteString("\n")
	return nil
}

// SetCryptoKey sets crypto key of this crypto hook
func (h *PlaintextFormatterHook) SetCryptoKey(key []byte) error {
	h.integrityCalculator.ResetCryptoKey(key)
	return nil
}

// PreFormat handler adds (if necessary) "end of chain" marker to the entry in order
// to cryptographically bound it to the integrity computation
func (h *PlaintextFormatterHook) PreFormat(entry *log.Entry) error {
	// we add EndOfChain marker into entry in pre-format stage because it should be cryptographically bounded to the log entry
	if entry.Message == EndOfAuditLogChainMessage {
		entry.Data[AuditLogChainKey] = EndAuditLogChainValue
	}
	return nil
}

// PostFormat handler adds integrity to output
func (h *PlaintextFormatterHook) PostFormat(entry *log.Entry, formatted *bytes.Buffer) error {
	// truncate `\n` added by Text formatter
	formatted.Truncate(formatted.Len() - 1)
	err := appendIntegrity(h.integrityCalculator, formatted)
	if err != nil {
		return err
	}
	formatted.WriteString("\n")
	return nil
}

func appendIntegrity(integrityCalculator *LogEntryIntegrityCalculator, formatted *bytes.Buffer) error {
	integrity, newChain, err := integrityCalculator.CalculateIntegrityCheck(formatted.Bytes())
	if err != nil {
		return err
	}
	formatted.WriteString(SpaceDelimiter + IntegrityKey + EquallyDelimiter)
	formatted.WriteString(hex.EncodeToString(integrity))
	if newChain {
		formatted.WriteString(SpaceDelimiter + NewAuditLogChainSuffix)
	}
	return nil
}

// ReadLogEntries sequentially reads log entries from provided file list and pushes them into a channel
func ReadLogEntries(absoluteFileNames []string, isMissingOk, debug bool) *LogEntrySource {
	// print order of input filenames
	if debug {
		for _, filename := range absoluteFileNames {
			log.Debug(filename)
		}
	}
	// push log entries from multiply files sequentially into channel
	output := make(chan *LogEntryInfo, 100)
	result := &LogEntrySource{
		Entries: output,
		Error:   nil,
	}
	go func() {
		defer func() {
			close(output)
		}()
		for _, absoluteFileName := range absoluteFileNames {
			err := processLogFile(absoluteFileName, output)
			if os.IsNotExist(err) {
				log.Warningln("file: ", absoluteFileName, "is missing")
				if isMissingOk {
					continue
				}
			}
			if err != nil {
				log.WithError(err).Errorln("unexpected error occurred while log file processing: ", absoluteFileName)
				result.Error = err
				return
			}
		}
	}()
	return result
}

func processLogFile(absoluteFileName string, output chan *LogEntryInfo) (err error) {
	f, err := os.Open(absoluteFileName)
	if err != nil {
		return err
	}
	defer func() {
		err2 := f.Close()
		if err == nil {
			err = err2
		}
	}()

	fileInfo, err := f.Stat()
	if err != nil {
		return err
	}
	lineNumber := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		logEntryInfo := &LogEntryInfo{
			RawLogEntry: scanner.Text(),
			FileInfo:    fileInfo,
			LineNumber:  lineNumber,
		}
		output <- logEntryInfo
		lineNumber++
	}
	return nil
}
