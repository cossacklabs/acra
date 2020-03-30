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
// Logging mode and verbosity level can be configured for AcraServer, AcraConnector, and AcraWebConfig in the
// corresponding yaml files or passed as CLI parameter.
//
// https://github.com/cossacklabs/acra/wiki/Logging
package logging

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Log modes
const (
	LogDebug = iota
	LogVerbose
	LogDiscard
)

const (
	PlaintextFormatString = "plaintext"
	JsonFormatString      = "json"
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

// FormatterWrapper wraps log.Formatter interface and adds functions for customizations.
// Intention for this interface is to provide ability to customize logging by accustomed:
// `logging.SetServiceName` / `logging.SetHooks` from main function of Acra services
type FormatterWrapper interface {
	log.Formatter
	SetServiceName(serviceName string)
	SetHooks(hooks []FormatterHook)
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
func CreateFormatter(format string) FormatterWrapper {
	var formatter FormatterWrapper
	switch strings.ToLower(format) {
	case JsonFormatString:
		formatter = JSONFormatter()
	case CefFormatString:
		formatter = CEFFormatter()
	default:
		formatter = TextFormatter()
	}
	log.SetFormatter(formatter)
	return formatter
}

// SetServiceName adds service-name label to log entries
// (plaintext formatter ignores it)
func SetServiceName(formatter FormatterWrapper, serviceName string) {
	formatter.SetServiceName(serviceName)
}

// SetHooks allows further customizations for logging
func SetHooks(formatter FormatterWrapper, hooks []FormatterHook) {
	formatter.SetHooks(hooks)
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
