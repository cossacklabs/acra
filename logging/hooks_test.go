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

package logging

import (
	"bytes"
	"fmt"
	"github.com/cossacklabs/acra/utils"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

type stubFormatterHook struct {
	WhenWillFormat func(entry *log.Entry) error
	WhenDidFormat  func(entry *log.Entry, formatted *bytes.Buffer) error
}

func (m *stubFormatterHook) PreFormat(entry *log.Entry) error {
	if m.WhenWillFormat != nil {
		return m.WhenWillFormat(entry)
	}
	return nil
}

func (m *stubFormatterHook) PostFormat(entry *log.Entry, formatted *bytes.Buffer) error {
	if m.WhenDidFormat != nil {
		return m.WhenDidFormat(entry, formatted)
	}
	return nil
}

func demoLogEntry() *log.Entry {
	entry := log.WithFields(log.Fields{
		"a-field": "value A",
		"z-field": "value Z",
	})
	entry.Time, _ = time.Parse(time.RFC3339, "1986-10-04T23:59:59Z")
	entry.Level = log.ErrorLevel
	entry.Message = "test error please ignore"
	return entry
}

func demoHooks(t *testing.T) []FormatterHook {
	return []FormatterHook{&stubFormatterHook{
		WhenWillFormat: func(entry *log.Entry) error {
			if entry.Data["a-field"] != "value A" {
				t.Error("invalid a-field value")
			}
			entry.Data["extra"] = "field"
			return nil
		},
		WhenDidFormat: func(entry *log.Entry, formatted *bytes.Buffer) error {
			if entry.Data["extra"] != "field" {
				t.Error("invalid extra field value")
			}
			newline := strings.HasSuffix(formatted.String(), "\n")
			if newline {
				formatted.Truncate(formatted.Len() - 1)
			}
			formatted.WriteString(fmt.Sprintf(" (total: %d fields)", len(entry.Data)))
			if newline {
				formatted.WriteString("\n")
			}
			entry.Data["missing"] = "from log"
			return nil
		},
	}}
}

func TestHooksPlaintext(t *testing.T) {
	f := TextFormatter()
	f.SetHooks(demoHooks(t))
	serialized, err := f.Format(demoLogEntry())
	if err != nil {
		t.Errorf("formatting failed: %v", err)
	}

	logLine := strings.TrimSpace(string(serialized))
	if logLine != `time="1986-10-04T23:59:59Z" level=error msg="test error please ignore" a-field="value A" extra=field z-field="value Z" (total: 3 fields)` {
		t.Errorf("incorrect log line: %v", string(serialized))
	}
}

func TestHooksCEF(t *testing.T) {
	f := CEFFormatter()
	f.SetServiceName("add one more field to cef formatter")
	f.SetHooks(demoHooks(t))
	serialized, err := f.Format(demoLogEntry())
	if err != nil {
		t.Errorf("formatting failed: %v", err)
	}

	logLine := strings.TrimSpace(string(serialized))
	expectedLine := `CEF:0|cossacklabs|add one more field to cef formatter|x.xx.x|100|test error please ignore|6|a-field=value A extra=field unixTime=528854399.000 z-field=value Z  (total: 8 fields)`
	expectedLine = strings.Replace(expectedLine, "x.xx.x", utils.VERSION, 1)
	if logLine != expectedLine {
		t.Errorf("incorrect log line: %v != %v\n", logLine, expectedLine)
	}
}

func TestHooksJSON(t *testing.T) {
	f := JSONFormatter()
	f.SetServiceName("add one more field to json formatter")
	f.SetHooks(demoHooks(t))
	serialized, err := f.Format(demoLogEntry())
	if err != nil {
		t.Errorf("formatting failed: %v", err)
	}

	logLine := strings.TrimSpace(string(serialized))
	expectedLine := `{"a-field":"value A","extra":"field","level":"error","msg":"test error please ignore","product":"add one more field to json formatter","timestamp":"1986-10-04T23:59:59Z","unixTime":"528854399.000","version":"x.xx.x","z-field":"value Z"} (total: 6 fields)`
	expectedLine = strings.Replace(expectedLine, "x.xx.x", utils.VERSION, 1)
	if logLine != expectedLine {
		t.Errorf("incorrect log line: %v != %v\n", logLine, expectedLine)
	}
}

func TestHooksWillFail(t *testing.T) {
	thisError := fmt.Errorf("my error")
	hooks := []FormatterHook{&stubFormatterHook{
		WhenWillFormat: func(entry *log.Entry) error {
			return thisError
		},
	}}
	f := TextFormatter()
	f.SetHooks(hooks)

	serialized, err := f.Format(demoLogEntry())
	if err != thisError {
		t.Errorf("formatting did not fail: %v => %v", err, string(serialized))
	}
}

func TestHooksDidFail(t *testing.T) {
	thisError := fmt.Errorf("my error")
	hooks := []FormatterHook{&stubFormatterHook{
		WhenDidFormat: func(entry *log.Entry, formatted *bytes.Buffer) error {
			return thisError
		},
	}}
	f := TextFormatter()
	f.SetHooks(hooks)

	serialized, err := f.Format(demoLogEntry())
	if err != thisError {
		t.Errorf("formatting did not fail: %v => %v", err, string(serialized))
	}
}
