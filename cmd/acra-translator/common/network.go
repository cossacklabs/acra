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

package common

import (
	"github.com/prometheus/client_golang/prometheus"
	"net"
)

// MetricConnectionCallback callback used for new incoming connections from gRPC or http.Server connection handlers and wraps
// new connections with time tracking of lifetime on Close calls
type MetricConnectionCallback struct {
	connectionType string
}

// NewMetricConnectionCallback return initialized MetricConnectionCallback with proper connectionType
func NewMetricConnectionCallback(connectionType string) *MetricConnectionCallback {
	return &MetricConnectionCallback{connectionType: connectionType}
}

// OnConnection callback for new connections for HTTPConnectionWrapper and http.Server connections
func (conn *MetricConnectionCallback) OnConnection(newConn net.Conn) (net.Conn, error) {
	return newConnectionMetric(conn.connectionType, newConn), nil
}

// OnServerHandshake callback for new connections for HTTPConnectionWrapper and gRPC connections
func (conn *MetricConnectionCallback) OnServerHandshake(newConn net.Conn) (net.Conn, error) {
	return newConnectionMetric(conn.connectionType, newConn), nil
}

// ConnectionMetric used to track connection time of life
type ConnectionMetric struct {
	net.Conn
	timer *prometheus.Timer
}

// newConnectionMetric wrap connection with metric and specific label
func newConnectionMetric(connectionType string, conn net.Conn) *ConnectionMetric {
	connectionCounter.WithLabelValues(connectionType).Inc()
	return &ConnectionMetric{Conn: conn, timer: prometheus.NewTimer(prometheus.ObserverFunc(connectionProcessingTimeHistogram.WithLabelValues(connectionType).Observe))}
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
