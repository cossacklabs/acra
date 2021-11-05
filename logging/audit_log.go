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
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
	"strings"
	"sync"
)

// LogEntryIntegrityCalculator implements audit log with hash generation with configured secret key
type LogEntryIntegrityCalculator struct {
	cryptoKey                      []byte
	previousLogEntryIntegrityCheck []byte
	mutex                          *sync.Mutex
}

// NewLogEntryIntegrityCalculator return new LogEntryIntegrityCalculator with configured secret key
func NewLogEntryIntegrityCalculator(key []byte) *LogEntryIntegrityCalculator {
	return &LogEntryIntegrityCalculator{
		cryptoKey:                      calculateHash(key),
		previousLogEntryIntegrityCheck: nil,
		mutex:                          &sync.Mutex{},
	}
}

func (f *LogEntryIntegrityCalculator) firstCheck() bool {
	return f.previousLogEntryIntegrityCheck == nil
}

// ResetCryptoKey reset calculator internal state and setup new secret key
func (f *LogEntryIntegrityCalculator) ResetCryptoKey(key []byte) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.cryptoKey = calculateHash(key)
	f.previousLogEntryIntegrityCheck = nil
}

// CalculateIntegrityCheck calculate integrity hash, return hash, flag is created new hash cycle and error if something went wrong
func (f *LogEntryIntegrityCalculator) CalculateIntegrityCheck(input []byte) ([]byte, bool, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	newChain := f.firstCheck()

	// Calculate Integrity check for log entry and save it as previous
	integrityCheck := f.calculateHmac(input)
	f.previousLogEntryIntegrityCheck = integrityCheck
	aggregatedIntegrityCheck := calculateHash(integrityCheck)

	// Update hmac key
	newKey := calculateHash(f.cryptoKey)
	f.cryptoKey = newKey

	return aggregatedIntegrityCheck, newChain, nil
}

func calculateHash(input []byte) []byte {
	result := sha256.Sum256(input)
	return result[:]
}

func (f *LogEntryIntegrityCalculator) calculateHmac(input []byte) []byte {
	h := hmac.New(sha256.New, f.cryptoKey)
	h.Write(input)
	h.Write(f.previousLogEntryIntegrityCheck)
	return h.Sum(nil)
}

// CreateCryptoFormatter creates formatter object
func CreateCryptoFormatter(format string) *AcraCryptoFormatter {
	var formatter *AcraCryptoFormatter
	switch strings.ToLower(format) {
	case JSONFormatString:
		formatter = NewCryptoFormatter(JSONFormatter())
	case CefFormatString:
		formatter = NewCryptoFormatter(CEFFormatter())
	default:
		formatter = NewCryptoFormatter(TextFormatter())
	}
	return formatter
}

// AuditLogKeySetter is an auxiliary interface used for decorating formatter's hook
type AuditLogKeySetter interface {
	SetCryptoKey(key []byte) error
}

// AcraCryptoFormatter is an implementation of formatter with crypto hook
type AcraCryptoFormatter struct {
	Formatter
}

// SetServiceName sets service name
func (f *AcraCryptoFormatter) SetServiceName(serviceName string) {
	f.Formatter.SetServiceName(serviceName)
}

// SetHooks sets hooks
func (f *AcraCryptoFormatter) SetHooks(hooks []FormatterHook) {
	f.Formatter.SetHooks(hooks)
}

// CryptoFormatter is an auxiliary interface that decorates usual formatter's hook with crypto key setter
type CryptoFormatter interface {
	Formatter
	AuditLogKeySetter
}

// NewCryptoFormatter creates new crypto formatter
func NewCryptoFormatter(formatter Formatter) *AcraCryptoFormatter {
	return &AcraCryptoFormatter{Formatter: formatter}
}

// ErrMissingCryptoHook is an error that occurs if hook with crypto abilities is not found in a set of formatter's hooks
var ErrMissingCryptoHook = errors.New("crypto hook is missing")

// SetCryptoKey is an implementation of crypto key setter
func (f *AcraCryptoFormatter) SetCryptoKey(key []byte) (err error) {
	err = ErrMissingCryptoHook
	for _, hook := range f.Formatter.GetHooks() {
		if cryptoHook, ok := hook.(AuditLogKeySetter); ok {
			err = cryptoHook.SetCryptoKey(key)
			if err != nil {
				return err
			}
		}
	}
	return
}

// AuditLogHandler is a coordinator of both formatter and writer objects. It's main purpose is 1) making
// log entries formatting and writing atomically and 2) to provide convenient methods for audit log
// functionality usage by acra services. It also guarantees that audit log chain can't be broken (started, but not finalized and vice versa)
type AuditLogHandler struct {
	formatter *AcraCryptoFormatter
	writer    io.Writer
	mutex     sync.Mutex
	key       []byte
	entry     *log.Entry
}

// NewAuditLogHandler creates new handler
func NewAuditLogHandler(formatter *AcraCryptoFormatter, writer io.Writer) (*AuditLogHandler, error) {
	handler := &AuditLogHandler{
		formatter,
		writer,
		sync.Mutex{},
		nil,
		nil,
	}
	return handler, nil
}

// Write is a version of typical Write which is used by logrus with it's internal lock
func (h *AuditLogHandler) Write(input []byte) (int, error) {
	n, err := h.writer.Write(input)
	if h.entry.Message == EndOfAuditLogChainMessage && h.key != nil {
		// here we can guarantee that crypto key will be reset for next log entry,
		// because this Write is called under logrus's lock
		err := h.formatter.SetCryptoKey(h.key)
		if err != nil {
			return 0, err
		}
	}
	return n, err
}

// Format is a version of typical Format which is used by logrus with it's internal lock
func (h *AuditLogHandler) Format(e *log.Entry) ([]byte, error) {
	h.entry = e
	return h.formatter.Format(e)
}

// FinalizeChain finalizes current audit log chain
func (h *AuditLogHandler) FinalizeChain() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	sendServiceLogs()
}

// ResetChain finalizes current chain if if necessary and starts new audit log chain
func (h *AuditLogHandler) ResetChain(key []byte) {
	// lock this operation, to prevent case when concurrent goroutine may wedge log message before resetting crypto key
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.key = key
	sendServiceLogs()
	h.key = nil
}

func sendServiceLogs() {
	// we use additional message here (for preparing), to prevent situation
	// when EndOfAuditLogChainMessage service message appears first in new chain
	withVerboseLogs(func() {
		log.Infof("Prepare to audit log chain finalization")
		log.Infof(EndOfAuditLogChainMessage)
	})
}

func withVerboseLogs(thunk func()) {
	previousLevel := GetLogLevel()
	defer SetLogLevel(previousLevel)
	SetLogLevel(LogVerbose)
	thunk()
}
