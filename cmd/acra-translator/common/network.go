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
	"context"
	logging "github.com/cossacklabs/acra/logging"
	"github.com/prometheus/client_golang/prometheus"
	"net"
)

// AcceptConnections return channel which will produce new connections from listener in background goroutine
func AcceptConnections(parentContext context.Context, listener net.Listener, errCh chan<- error) (<-chan net.Conn, error) {
	logger := logging.GetLoggerFromContext(parentContext)
	connectionChannel := make(chan net.Conn)

	// Run goroutine that just accept connections and return them and stop on error.
	// We need to have a control under this goroutine while shutdown process but we can't rely on
	// parentContext.Done since this event comes later that closing listener that accepts (we use listener
	// provided by caller, and caller is responsible for closing it).
	// For this reason we assume that *net.OpError == "accept" in case of accepting error
	// is normal case when shutdown is invoked

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// https://stackoverflow.com/questions/13417095/how-do-i-stop-a-listening-server-in-go
				if operationalError, ok := err.(*net.OpError); ok && operationalError.Op == "accept" {
					// This is a normal case, when listener is closed while it accepts, so just return
					logger.Infoln("Listener has been stopped by caller while accepting")
				} else {
					logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantAcceptNewConnections).WithError(err).Errorln("Error on accept connection")
					errCh <- err
				}
				return
			}
			conn, err = wrapHTTPConnectionWithTimer(conn)
			if err != nil {
				logger.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorCantWrapConnectionWithTimer).WithError(err).Errorln("Can't wrap connection with metric")
				errCh <- err
				return
			}
			connectionChannel <- conn
		}
	}()

	return connectionChannel, nil
}

// SecureSessionListenerWithMetrics wrap SecureSessionListener and collect metrics from accepted connections
type SecureSessionListenerWithMetrics struct {
	net.Listener
}

// WrapListenerWithMetrics wraps SecureSessionListener to collect metrics from connections
func WrapListenerWithMetrics(listener net.Listener) net.Listener {
	return &SecureSessionListenerWithMetrics{Listener: listener}
}

// Accept new connection and wrap with secure session and collecting metrics
// return ConnectionWrapError if error wa
func (listener *SecureSessionListenerWithMetrics) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return wrapGrpcConnectionWithTimer(conn)
}

// ConnectionMetric used to track connection time of life
type ConnectionMetric struct {
	net.Conn
	timer *prometheus.Timer
}

// newConnectionMetric wrap connection with metric and specific label
func newConnectionMetric(connectionType string, conn net.Conn) *ConnectionMetric {
	return &ConnectionMetric{Conn: conn, timer: prometheus.NewTimer(prometheus.ObserverFunc(connectionProcessingTimeHistogram.WithLabelValues(connectionType).Observe))}
}

// wrapGrpcConnectionWithTimer wrap conn with ConnectionMetric and grpcConnectionType label value
func wrapGrpcConnectionWithTimer(conn net.Conn) (net.Conn, error) {
	connectionCounter.WithLabelValues(grpcConnectionType).Inc()
	return newConnectionMetric(grpcConnectionType, conn), nil
}

// wrapHTTPConnectionWithTimer wrap conn with ConnectionMetric and httpConnectionType label value
func wrapHTTPConnectionWithTimer(conn net.Conn) (net.Conn, error) {
	connectionCounter.WithLabelValues(httpConnectionType).Inc()
	return newConnectionMetric(httpConnectionType, conn), nil
}

// Close call Close() of wrapped connection and track time of connection life
func (conn *ConnectionMetric) Close() error {
	conn.timer.ObserveDuration()
	return conn.Conn.Close()
}
