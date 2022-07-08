// Copyright 2022, Cossack Labs Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package network

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricConnectionCallback callback used for new incoming connections from gRPC
// or http.Server connection handlers and wraps new connections with time
// tracking of lifetime on Close calls
type MetricConnectionCallback struct {
	connectionType string
	counter        *prometheus.CounterVec
	histogram      *prometheus.HistogramVec
}

// NewMetricConnectionCallback return initialized MetricConnectionCallback with
// proper connectionType.
// When connection is processed, the counter is incremented and the histogram
// registers the duration of the connection.
func NewMetricConnectionCallback(connectionType string, counter *prometheus.CounterVec, histogram *prometheus.HistogramVec) *MetricConnectionCallback {
	return &MetricConnectionCallback{
		connectionType: connectionType,
		counter:        counter,
		histogram:      histogram,
	}
}

// OnConnection callback for new connections for HTTPConnectionWrapper and http.Server connections
func (conn *MetricConnectionCallback) OnConnection(newConn net.Conn) (net.Conn, error) {
	return newConnectionMetric(conn.connectionType, conn.counter, conn.histogram, newConn), nil
}

// OnServerHandshake callback for new connections for HTTPConnectionWrapper and gRPC connections
func (conn *MetricConnectionCallback) OnServerHandshake(newConn net.Conn) (net.Conn, error) {
	return newConnectionMetric(conn.connectionType, conn.counter, conn.histogram, newConn), nil
}

// ConnectionMetric used to track connection time of life
type ConnectionMetric struct {
	net.Conn
	timer *prometheus.Timer
}

// newConnectionMetric wrap connection with metric and specific label
func newConnectionMetric(connectionType string, counter *prometheus.CounterVec, histogram *prometheus.HistogramVec, conn net.Conn) *ConnectionMetric {
	counter.WithLabelValues(connectionType).Inc()
	observer := histogram.WithLabelValues(connectionType).Observe
	return &ConnectionMetric{Conn: conn, timer: prometheus.NewTimer(prometheus.ObserverFunc(observer))}
}

// Close call Close() of wrapped connection and track time of connection life
func (conn *ConnectionMetric) Close() error {
	conn.timer.ObserveDuration()
	return conn.Conn.Close()
}

// Unwrap returns wrapped connection
func (conn *ConnectionMetric) Unwrap() net.Conn {
	return conn.Conn
}
