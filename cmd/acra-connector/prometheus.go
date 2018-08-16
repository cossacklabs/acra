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
package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
)

const (
	connectionTypeLabel = "connection_type"
	apiConnectionType   = "api"
	dbConnectionType    = "db"
)

var (
	connectionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acraconnector_connections_total",
			Help: "number of connections to database",
		}, []string{connectionTypeLabel})

	connectionProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acraconnector_connections_processing_seconds",
		Help:    "Time of connection processing",
		Buckets: []float64{0.1, 0.2, 0.5, 1, 10, 60, 3600, 86400},
	}, []string{connectionTypeLabel})
)

var registerLock = sync.Once{}

func registerMetrics() {
	registerLock.Do(func() {
		prometheus.MustRegister(connectionCounter)
		prometheus.MustRegister(connectionProcessingTimeHistogram)
	})
}
