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
	"context"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"regexp"
)

// reZero provides a simple way to detect an empty ID
// took from go.opencensus.io/examples/exporter/exporter.go
var reZero = regexp.MustCompile(`^0+$`)

// LogSpanExporter exporter for opencensus that print all spans with logger
type LogSpanExporter struct{}

// ExportSpan log the trace span
func (e *LogSpanExporter) ExportSpan(vd *trace.SpanData) {
	// todo use some lru cache for hex values of traceID/SpanID
	var (
		traceID      = hex.EncodeToString(vd.SpanContext.TraceID[:])
		spanID       = hex.EncodeToString(vd.SpanContext.SpanID[:])
		parentSpanID = hex.EncodeToString(vd.ParentSpanID[:])
	)
	logger := log.WithFields(log.Fields{"trace_id": traceID, "span_id": spanID, "span_name": vd.Name, "duration": nanosecondsToMillisecondsString(int64(vd.EndTime.Sub(vd.StartTime)))})
	if vd.Status.Code != trace.StatusCodeOK {
		logger = logger.WithFields(log.Fields{"status_message": vd.Status.Message, "status_code": vd.Status.Code})
	}

	if !reZero.MatchString(parentSpanID) {
		logger = logger.WithField("parent_span_id", parentSpanID)
	}

	linkFields := log.Fields{}
	for i, link := range vd.Links {
		linkFields[fmt.Sprintf("link_trace_id_%v", i)] = link.TraceID
		linkFields[fmt.Sprintf("link_span_id_%v", i)] = link.SpanID
		linkFields[fmt.Sprintf("link_span_type_%v", i)] = link.Type
		// TODO handle link.Attributes
	}
	logger = logger.WithFields(linkFields)

	if len(vd.Attributes) > 0 {
		attributes := log.Fields{}
		for k, v := range vd.Attributes {
			attributes[k] = v
		}
		logger = logger.WithFields(attributes)
	}

	if len(vd.Annotations) > 0 {
		for _, item := range vd.Annotations {
			annotations := log.Fields{FieldKeyUnixTime: TimeToString(item.Time)}
			for k, v := range item.Attributes {
				annotations[k] = v
			}
			logger.WithFields(annotations).Infoln(item.Message)
		}
	}
	logger.Infoln("span end")
}

// LoggerWithTrace return logger with added span_id/trace_id fields from context
func LoggerWithTrace(context context.Context, logger *log.Entry) *log.Entry {
	span := trace.FromContext(context)
	spanContext := span.SpanContext()
	if getTraceStatus(context) {
		return logger.WithFields(log.Fields{"span_id": spanContext.SpanID, "trace_id": spanContext.TraceID})
	}
	return logger

}

// NewLoggerWithTrace return logger with trace_id/span_id fields
func NewLoggerWithTrace(context context.Context) *log.Entry {
	return LoggerWithTrace(context, log.NewEntry(log.StandardLogger()))
}

// traceStatusKey used as key for context value
type traceStatusKey struct{}

// SetTraceStatus to context
func SetTraceStatus(ctx context.Context, isOn bool) context.Context {
	return context.WithValue(ctx, traceStatusKey{}, isOn)
}

// getTraceStatus return status of tracing or false if not set
func getTraceStatus(ctx context.Context) bool {
	value := ctx.Value(traceStatusKey{})
	if v, ok := value.(bool); ok {
		return v
	}
	return false
}
