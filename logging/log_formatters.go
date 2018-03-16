package logging

import (
	"github.com/sirupsen/logrus"
	"time"
	"sync"
	"github.com/cossacklabs/acra/utils"
	"fmt"
)


// ---------- custom Loggers
// inspired by "github.com/bshuster-repo/logrus-logstash-hook"
// ----------



// TextFormatter returns a default logrus.TextFormatter with specific settings
func TextFormatter() logrus.Formatter {
	return &logrus.TextFormatter{
		FullTimestamp:    true,
		TimestampFormat:  time.RFC3339,
		QuoteEmptyFields: true}
}


// JSONFormatter returns a AcraJSONFormatter
func JSONFormatter(fields logrus.Fields) logrus.Formatter {
	for k, v := range extraJSONFields {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}

	return AcraJSONFormatter{
		Formatter: &logrus.JSONFormatter{
			FieldMap:        JSONFieldMap,
			TimestampFormat: time.RFC3339,
		},
		Fields: fields,
	}
}


// CEFFormatter returns a AcraCEFFormatter
func CEFFormatter(fields logrus.Fields) logrus.Formatter {
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

	return AcraCEFFormatter{
		CEFTextFormatter: CEFTextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		},
		Fields: fields,
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


// AcraCustomFormatter represents a format with specific fields.
// It has logrus.Formatter which formats the entry and logrus.Fields which
// are added to the JSON/CEF message if not given in the entry data.
//
// Note: use the `JSONFormatter` function to set a default AcraJSON formatter.
type AcraJSONFormatter struct {
	logrus.Formatter
	logrus.Fields
}

type AcraCEFFormatter struct {
	CEFTextFormatter
	logrus.Fields
}

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
		FieldKeyEventCode: 0,
	}

	JSONFieldMap = logrus.FieldMap{
		logrus.FieldKeyTime:  "timestamp",
		logrus.FieldKeyMsg:   "msg",
		logrus.FieldKeyLevel: "level",
	}
)

// Format formats an entry to a AcraJSON format according to the given Formatter and Fields.
//
// Note: the given entry is copied and not changed during the formatting process.
func (f AcraJSONFormatter) Format(e *logrus.Entry) ([]byte, error) {
	// unix time
	f.Fields[FieldKeyUnixTime] = unixTimeWithMilliseconds(e)

	ne := copyEntry(e, f.Fields)
	dataBytes, err := f.Formatter.Format(ne)
	releaseEntry(ne)
	return dataBytes, err
}


// Format formats an entry to a AcraCEF format according to the given Formatter and Fields.
//
// Note: the given entry is copied and not changed during the formatting process.
func (f AcraCEFFormatter) Format(e *logrus.Entry) ([]byte, error) {
	// unix time
	f.Fields[FieldKeyUnixTime] = unixTimeWithMilliseconds(e)

	ne := copyEntry(e, f.Fields)
	dataBytes, err := f.CEFTextFormatter.Format(ne)
	releaseEntry(ne)
	return dataBytes, err
}


func unixTimeWithMilliseconds(e *logrus.Entry) string {
	//secs := e.Time.Unix()
	nanos := e.Time.UnixNano()
	millis := nanos / 1000000
	millisf := float64(millis) / 1000.0

	return fmt.Sprintf("%.3f", millisf)
}