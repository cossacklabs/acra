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
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/decryptor/base"
	"github.com/cossacklabs/acra/utils"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
)

const (
	requestTypeLabel = "request_type"
	// HTTPRequestType http type of request for metric label
	HTTPRequestType = "http"
	// GrpcRequestType grpc type of request for metric label
	GrpcRequestType = "grpc"
)

const (
	connectionTypeLabel = "connection_type"
	httpConnectionType  = "http"
	grpcConnectionType  = "grpc"
)

var (
	// RequestProcessingTimeHistogram collect metrics about time of processing requests to http/grpc api
	RequestProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acratranslator_request_processing_seconds",
		Help:    "Time of response processing",
		Buckets: []float64{0.000001, 0.00001, 0.00002, 0.00003, 0.00004, 0.00005, 0.00006, 0.00007, 0.00008, 0.00009, 0.0001, 0.0005, 0.001, 0.005, 0.01, 1},
	}, []string{requestTypeLabel})
)

var (
	connectionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acratranslator_connections_total",
			Help: "number of connections to database",
		}, []string{connectionTypeLabel})

	connectionProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acratranslator_connections_processing_seconds",
		Help:    "Time of connection processing",
		Buckets: []float64{0.1, 0.2, 0.5, 1, 10, 60, 3600, 86400},
	}, []string{connectionTypeLabel})
)

var registerLock = sync.Once{}

// RegisterMetrics register metrics in prometheus exporter related with translator
func RegisterMetrics(serviceName string) {
	registerLock.Do(func() {
		prometheus.MustRegister(connectionCounter)
		prometheus.MustRegister(connectionProcessingTimeHistogram)
		prometheus.MustRegister(RequestProcessingTimeHistogram)
		base.RegisterAcraStructProcessingMetrics()
		version, err := utils.GetParsedVersion()
		if err != nil {
			panic(err)
		}
		cmd.RegisterVersionMetrics(serviceName, version)
		cmd.RegisterBuildInfoMetrics(serviceName, utils.CommunityEdition)
	})
}
