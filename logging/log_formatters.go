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

package logging

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/cossacklabs/acra/utils"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// ---------- custom Loggers
// inspired by "github.com/bshuster-repo/logrus-logstash-hook"
// ----------

// TextFormatter returns a default logrus.TextFormatter with specific settings
func TextFormatter() Formatter {
	return &AcraTextFormatter{
		Formatter: &logrus.TextFormatter{
			FullTimestamp:    true,
			TimestampFormat:  time.RFC3339,
			QuoteEmptyFields: true,
		},
		Hooks: nil,
	}
}

// JSONFormatter returns a default logrus.JSONFormatter with specific settings
func JSONFormatter() Formatter {
	return &AcraJSONFormatter{
		Formatter: &logrus.JSONFormatter{
			FieldMap:        JSONFieldMap,
			TimestampFormat: time.RFC3339,
		},
		Hooks:  nil,
		Fields: nil,
	}
}

// CEFFormatter returns a default CEFTextFormatter with specific settings
func CEFFormatter() Formatter {
	return &AcraCEFFormatter{
		CEFTextFormatter: CEFTextFormatter{
			TimestampFormat: time.RFC3339,
		},
		Fields: nil,
		Hooks:  nil,
	}
}

// ---------------------------

// Using a pool to re-use of old entries when formatting messages.
// It is used in the Fire function.
var entryPool = sync.Pool{
	New: func() interface{} {
		return &logrus.Entry{}
	},
}

// copyEntry copies the entry `e` to a new entry and then adds all the fields in `fields` that are missing in the new entry data.
// It uses `entryPool` to re-use allocated entries.
func copyEntry(e *logrus.Entry, fields logrus.Fields) *logrus.Entry {
	ne := entryPool.Get().(*logrus.Entry)
	ne.Message = e.Message
	ne.Level = e.Level
	ne.Time = e.Time
	ne.Data = logrus.Fields{}
	for k, v := range fields {
		ne.Data[k] = v
	}
	for k, v := range e.Data {
		ne.Data[k] = v
	}
	return ne
}

// releaseEntry puts the given entry back to `entryPool`. It must be called if copyEntry is called.
func releaseEntry(e *logrus.Entry) {
	entryPool.Put(e)
}

// AcraTextFormatter provides log formatting as plaintext.
//
// Hooks may be used for additional post-processing of entries.
//
// Use `TextFormatter` to instantiate AcraTextFormatter.
type AcraTextFormatter struct {
	logrus.Formatter
	Hooks []FormatterHook
}

// SetServiceName set service name
func (f *AcraTextFormatter) SetServiceName(serviceName string) {
	// service name is ignored by plaintext formatter, so just do nothing
}

// SetHooks set formatter hooks
func (f *AcraTextFormatter) SetHooks(hooks []FormatterHook) {
	f.Hooks = hooks
}

// GetHooks get formatter hooks
func (f *AcraTextFormatter) GetHooks() []FormatterHook {
	return f.Hooks
}

// AcraJSONFormatter represents a format with specific fields.
//
// It has logrus.Formatter which formats the entry and logrus.Fields which
// are added to the JSON/CEF message if not given in the entry data.
//
// Hooks may be used for more fine-tuned post-processing of entries.
//
// Note: use the `JSONFormatter` function to set a default AcraJSON formatter.
type AcraJSONFormatter struct {
	logrus.Formatter
	logrus.Fields
	Hooks []FormatterHook
}

// SetServiceName set service name
func (f *AcraJSONFormatter) SetServiceName(serviceName string) {
	fields := log.Fields{FieldKeyProduct: serviceName}
	for k, v := range extraJSONFields {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}
	f.Fields = fields
}

// SetHooks set formatter hooks
func (f *AcraJSONFormatter) SetHooks(hooks []FormatterHook) {
	f.Hooks = hooks
}

// GetHooks get formatter hooks
func (f *AcraJSONFormatter) GetHooks() []FormatterHook {
	return f.Hooks
}

// AcraCEFFormatter is based on CEFTextFormatter with extra logrus fields.
//
// Hooks may be used for more fine-tuned post-processing of entries.
type AcraCEFFormatter struct {
	CEFTextFormatter
	logrus.Fields
	Hooks []FormatterHook
}

// SetServiceName set service name
func (f *AcraCEFFormatter) SetServiceName(serviceName string) {
	fields := log.Fields{FieldKeyProduct: serviceName}
	for k, v := range extraJSONFields {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}
	for k, v := range extraCEFFields {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}
	f.Fields = fields
}

// SetHooks set formatter hooks
func (f *AcraCEFFormatter) SetHooks(hooks []FormatterHook) {
	f.Hooks = hooks
}

// GetHooks get formatter hooks
func (f *AcraCEFFormatter) GetHooks() []FormatterHook {
	return f.Hooks
}

// Constants showing extra filed added to loggers by default
var (
	// to be re-defined
	extraJSONFields = logrus.Fields{
		FieldKeyProduct:  "acra",
		FieldKeyUnixTime: 0,
		FieldKeyVersion:  utils.VERSION,
	}

	// to be re-defined
	extraCEFFields = logrus.Fields{
		FieldKeyVendor:    "cossacklabs",
		FieldKeyEventCode: EventCodeGeneral,
	}

	JSONFieldMap = logrus.FieldMap{
		logrus.FieldKeyTime:  "timestamp",
		logrus.FieldKeyMsg:   "msg",
		logrus.FieldKeyLevel: "level",
	}
)

// Format a log entry in standard plaintext format.
func (f *AcraTextFormatter) Format(e *logrus.Entry) ([]byte, error) {
	return formatEntry(e, f.Formatter, f.Hooks)
}

// Format formats an entry to a AcraJSON format according to the given Formatter and Fields.
//
// Note: the given entry is copied and not changed during the formatting process.
func (f AcraJSONFormatter) Format(e *logrus.Entry) ([]byte, error) {
	ne := copyEntry(e, f.Fields)
	if value, ok := ne.Data[FieldKeyUnixTime]; !ok || value == 0 {
		ne.Data[FieldKeyUnixTime] = unixTimeWithMilliseconds(e)
	}
	dataBytes, err := formatEntry(ne, f.Formatter, f.Hooks)
	releaseEntry(ne)
	return dataBytes, err
}

// Format formats an entry to a AcraCEF format according to the given Formatter and Fields.
//
// Note: the given entry is copied and not changed during the formatting process.
func (f *AcraCEFFormatter) Format(e *logrus.Entry) ([]byte, error) {
	ne := copyEntry(e, f.Fields)
	if value, ok := ne.Data[FieldKeyUnixTime]; !ok || value == 0 {
		ne.Data[FieldKeyUnixTime] = unixTimeWithMilliseconds(e)
	}
	dataBytes, err := formatEntry(ne, &f.CEFTextFormatter, f.Hooks)
	releaseEntry(ne)
	return dataBytes, err
}

// TimeToString return string representation of timestamp with milliseconds
func TimeToString(t time.Time) string {
	return nanosecondsToMillisecondsString(t.UnixNano())
}

func nanosecondsToMillisecondsString(nanos int64) string {
	millis := nanos / 1000000
	millisf := float64(millis) / 1000.0
	return fmt.Sprintf("%.3f", millisf)
}

func unixTimeWithMilliseconds(e *logrus.Entry) string {
	return TimeToString(e.Time)
}

func formatEntry(e *logrus.Entry, formatter log.Formatter, hooks []FormatterHook) ([]byte, error) {
	for _, hook := range hooks {
		err := hook.PreFormat(e)
		if err != nil {
			return nil, err
		}
	}
	serialized, err := formatter.Format(e)
	if err != nil {
		return nil, err
	}
	buffer := bytes.NewBuffer(serialized)
	for _, hook := range hooks {
		err := hook.PostFormat(e, buffer)
		if err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}
