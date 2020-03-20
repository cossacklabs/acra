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

const (
	LoggingFormatPlaintext = "plaintext"
	LoggingFormatJSON      = "json"
	LoggingFormatCEF       = "cef"
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

// CustomizeBuilder allows to customize logging process
type CustomizeBuilder struct {
	writer        io.Writer
	serviceName   string
	loggingFormat string
	hooks         []FormatterHook
}

// Customize is a global function for logging customization.
// Example of usage: Customize().SetServiceName(...).SetFormat(...).SetOutput(...).Complete()
func Customize() *CustomizeBuilder {
	return &CustomizeBuilder{}
}

// SetOutput specifies where logs should be written (stderr, file, etc.)
func (c *CustomizeBuilder) SetOutput(w io.Writer) *CustomizeBuilder {
	c.writer = w
	return c
}

// SetServiceName specifies global name of service that produces logs
func (c *CustomizeBuilder) SetServiceName(serviceName string) *CustomizeBuilder {
	c.serviceName = serviceName
	return c
}

// SetFormat specifies actual format
func (c *CustomizeBuilder) SetFormat(loggingFormat string) *CustomizeBuilder {
	c.loggingFormat = loggingFormat
	return c
}

// SetHooks specifies additional pre-/post-processing actions with log entries
func (c *CustomizeBuilder) SetHooks(hooks []FormatterHook) *CustomizeBuilder {
	c.hooks = hooks
	return c
}

// Complete finishes logging customization.
// For default logging use Customize().Complete()
func (c *CustomizeBuilder) Complete() {
	if c.writer == nil {
		c.writer = os.Stderr
	}
	if c.loggingFormat == "" {
		c.loggingFormat = LoggingFormatPlaintext
	}
	/* We do not check hooks field, since it can be nil (standard log entry processing) */
	log.SetOutput(c.writer)
	log.SetFormatter(logFormatterFor(c.loggingFormat, c.serviceName, c.hooks))
	log.Debugf("Changed logging format to %s", c.loggingFormat)
}

func logFormatterFor(loggingFormat string, serviceName string, hooks []FormatterHook) log.Formatter {
	switch strings.ToLower(loggingFormat) {
	case LoggingFormatJSON:
		return JSONFormatter(log.Fields{FieldKeyProduct: serviceName}, hooks)
	case LoggingFormatCEF:
		return CEFFormatter(log.Fields{FieldKeyProduct: serviceName}, hooks)
	default:
		return TextFormatter(hooks)
	}
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
