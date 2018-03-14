package logging

import (
	"github.com/sirupsen/logrus"
	"time"
	"sync"
	"github.com/cossacklabs/acra/utils"
)


// ---------- custom Loggers
// inspired by "github.com/bshuster-repo/logrus-logstash-hook"
// ----------


// TextFormatter returns a default logrus.TextFormatter with specific settings
func TextFormatter() logrus.Formatter {
	return &logrus.TextFormatter{
		FullTimestamp:    true,
		TimestampFormat:  time.RFC3339Nano,
		QuoteEmptyFields: true}
}


// JSONFormatter returns a AcraJSON formatter
func JSONFormatter(fields logrus.Fields) logrus.Formatter {
	for k, v := range extraJSONFields {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}

	return JSONFormatter{
		Formatter: &logrus.JSONFormatter{
			FieldMap:        JSONFieldMap,
			TimestampFormat: time.RFC3339Nano,
		},
		Fields: fields,
	}
}


// CustomCEFFormatter returns a AcraCEF formatter
func CustomCEFFormatter(fields logrus.Fields) logrus.Formatter {
	for k, v := range extraJSONFields {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}

	return CEFFormatter{
		Formatter: &logrus.TextFormatter {
			FullTimestamp:    true,
			TimestampFormat: time.RFC3339Nano,
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
	logrus.Formatter
	logrus.Fields
}

var (
	extraJSONFields = logrus.Fields{"product": "acra", "version": utils.VERSION} // to be re-defined
	JSONFieldMap    = logrus.FieldMap{
		logrus.FieldKeyTime:  "timestamp",
		logrus.FieldKeyMsg:   "msg",
		logrus.FieldKeyLevel: "severity",
	}
)

// Format formats an entry to a AcraJSON format according to the given Formatter and Fields.
//
// Note: the given entry is copied and not changed during the formatting process.
func (f AcraJSONFormatter) Format(e *logrus.Entry) ([]byte, error) {
	ne := copyEntry(e, f.Fields)
	dataBytes, err := f.Formatter.Format(ne)
	releaseEntry(ne)
	return dataBytes, err
}


// TODO: change how we format strings
// TODO: handle severity levels
// Format formats an entry to a AcraCEF format according to the given Formatter and Fields.
//
// Note: the given entry is copied and not changed during the formatting process.
func (f AcraCEFFormatter) Format(e *logrus.Entry) ([]byte, error) {
	ne := copyEntry(e, f.Fields)
	dataBytes, err := f.Formatter.Format(ne)
	releaseEntry(ne)
	return dataBytes, err
}

