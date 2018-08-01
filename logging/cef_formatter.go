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
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"sync"
	"time"
)

// Almost compatible with CEF doc
// https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/78000/KB78712/en_US/CEF_White_Paper_20100722.pdf
//
// Current implementation allows using any extension keys
//

const defaultTimestampFormat = time.RFC3339
const defaultCEFLogStart = "CEF:0"
const defaultHostName = "host"
const defaultMessageDivider = "|"

// Default key names for the default fields
const (
	FieldKeyUnixTime  = "unixTime"
	FieldKeyProduct   = "product"
	FieldKeyVersion   = "version"
	FieldKeySeverity  = "severity"
	FieldKeyVendor    = "vendor"
	FieldKeyEventCode = "code"
)

// CEFTextFormatter formats logs into text
type CEFTextFormatter struct {
	// TimestampFormat to use for display when a full timestamp is printed
	TimestampFormat string

	// QuoteEmptyFields will wrap empty fields in quotes if true
	QuoteEmptyFields bool

	// By default 'CEF:0'
	CEFPrefixString string

	// By default 'os.Hostname()'
	HostName string

	// start log with syslog prefix automatically
	ShouldAddSyslogPrefix bool

	sync.Once
}

func (f *CEFTextFormatter) init(entry *logrus.Entry) {
	f.ShouldAddSyslogPrefix = false
	f.QuoteEmptyFields = true
}

// Format renders a single log entry
func (f *CEFTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer

	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	f.Do(func() { f.init(entry) })

	timestampFormat := f.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = defaultTimestampFormat
	}

	hostname := f.HostName
	if hostname == "" {
		realHostName, err := os.Hostname()
		if err != nil {
			hostname = defaultHostName
		} else {
			hostname = realHostName
		}
	}

	// syslog prefix
	// timestamp host
	if f.ShouldAddSyslogPrefix {
		b.WriteString(entry.Time.Format(timestampFormat))
		b.WriteByte(' ')
		b.WriteString(hostname)
		b.WriteByte(' ')
	}

	// CEF:0
	b.WriteString(defaultCEFLogStart)

	// |Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
	f.appendCEFLogPiece(b, entry.Data[FieldKeyVendor])
	f.appendCEFLogPiece(b, entry.Data[FieldKeyProduct])
	f.appendCEFLogPiece(b, entry.Data[FieldKeyVersion])
	f.appendCEFLogPiece(b, entry.Data[FieldKeyEventCode])

	f.appendCEFLogPiece(b, entry.Message)
	f.appendCEFLogPiece(b, severityByLevel(entry.Level))

	b.WriteString(defaultMessageDivider)

	// Extension

	// actually, these fields should have only designated names according to the Extension Dictionary of CEF
	extensionKeys := otherExtensionKeys(entry.Data)
	for _, key := range extensionKeys {
		f.appendKeyValue(b, key, entry.Data[key])
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

func otherExtensionKeys(data logrus.Fields) []string {
	extensionKeys := make([]string, 0, len(data))
	for k := range data {

		if k != FieldKeyVendor && k != FieldKeyProduct && k != FieldKeyVersion &&
			k != FieldKeyEventCode && k != FieldKeySeverity {

			extensionKeys = append(extensionKeys, k)
		}
	}
	return extensionKeys
}

func (f *CEFTextFormatter) appendCEFLogPiece(b *bytes.Buffer, value interface{}) {
	b.WriteString(defaultMessageDivider)
	f.appendValue(b, value)
}

func (f *CEFTextFormatter) appendKeyValue(b *bytes.Buffer, key string, value interface{}) {
	preparedKey := prepareString(key)

	if f.needsQuoting(preparedKey) {
		preparedKey = fmt.Sprintf("%q", preparedKey)
	}

	b.WriteString(preparedKey)
	b.WriteByte('=')
	f.appendValue(b, value)
	b.WriteByte(' ')
}

func (f *CEFTextFormatter) appendValue(b *bytes.Buffer, value interface{}) {
	stringVal, ok := value.(string)
	if !ok {
		stringVal = fmt.Sprint(value)
	}

	stringVal = prepareString(stringVal)

	// CEF doesn't define using quotes
	if len(stringVal) == 0 {
		b.WriteString(" ")
	} else {
		b.WriteString(stringVal)
	}
}

func prepareString(value string) string {
	stringVal := fmt.Sprint(value)

	// is it a valid way to remove any \t\n even inside line?
	stringVal = strings.TrimSpace(stringVal)
	stringVal = strings.Replace(stringVal, "\n", " ", -1)
	stringVal = strings.Replace(stringVal, "\t", " ", -1)
	stringVal = strings.Replace(stringVal, `\`, `\\`, -1)
	stringVal = strings.Replace(stringVal, "|", `\|`, -1)
	stringVal = strings.Replace(stringVal, `=`, `\=`, -1)
	return stringVal
}

func severityByLevel(level logrus.Level) int {
	switch level {
	case logrus.DebugLevel:
		return 0
	case logrus.InfoLevel:
		return 1
	case logrus.WarnLevel:
		return 3
	case logrus.ErrorLevel:
		return 6
	case logrus.FatalLevel:
		return 8
	case logrus.PanicLevel:
		return 10
	}

	return 0
}

func (f *CEFTextFormatter) needsQuoting(text string) bool {
	if f.QuoteEmptyFields && len(text) == 0 {
		return true
	}
	for _, ch := range text {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.' || ch == '_' || ch == '/' || ch == '@' || ch == '^' || ch == '+') {
			return true
		}
	}
	return false
}
