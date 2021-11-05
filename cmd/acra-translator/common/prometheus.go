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
	"errors"
	"github.com/cossacklabs/acra/cmd"
	"github.com/cossacklabs/acra/decryptor/base"
	tokenCommon "github.com/cossacklabs/acra/pseudonymization/common"
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
	operationLabel             = "operation"
	encryptOperation           = "encrypt"
	decryptOperation           = "decrypt"
	encryptSearchableOperation = "encryptSearchable"
	decryptSearchableOperation = "decryptSearchable"

	encryptSymOperation           = "encryptSym"
	decryptSymOperation           = "decryptSym"
	encryptSymSearchableOperation = "encryptSymSearchable"
	decryptSymSearchableOperation = "decryptSymSearchable"

	generateQueryHashOperation = "generateQueryHash"

	tokenizeOperation   = "tokenize"
	detokenizeOperation = "detokenize"
)

// Valid values of connection type for metrics for Acra-Translator API
const (
	connectionTypeLabel = "connection_type"
	HTTPConnectionType  = "http"
	GRPCConnectionType  = "grpc"
)

var (
	// RequestProcessingTimeHistogram collect metrics about time of processing requests to http/grpc api
	RequestProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acratranslator_request_processing_seconds",
		Help:    "Time of response processing",
		Buckets: []float64{0.000001, 0.00001, 0.00002, 0.00003, 0.00004, 0.00005, 0.00006, 0.00007, 0.00008, 0.00009, 0.0001, 0.0005, 0.001, 0.005, 0.01, 1, 3, 5, 10},
	}, []string{requestTypeLabel, operationLabel})
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

type prometheusWrapper struct {
	ITranslatorService
	metricType string
}

// ErrInvalidMetricType used unsupported metric type.
var ErrInvalidMetricType = errors.New("unsupported metric type")

// NewPrometheusServiceWrapper wraps all methods of service with metrics that track time of execution
func NewPrometheusServiceWrapper(service ITranslatorService, metricType string) (ITranslatorService, error) {
	switch metricType {
	case HTTPRequestType, GrpcRequestType:
		return &prometheusWrapper{service, metricType}, nil
	}
	return nil, ErrInvalidMetricType
}

// Decrypt AcraStruct using passed ZoneID if length > 0 otherwise use ClientID (that is required after that)
func (wrapper *prometheusWrapper) Decrypt(ctx context.Context, acraStruct, clientID, zoneID []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, decryptOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.Decrypt(ctx, acraStruct, clientID, zoneID)
}

// Encrypt AcraStruct using passed ZoneID if length > 0 otherwise use ClientID (that is required after that)
func (wrapper *prometheusWrapper) Encrypt(ctx context.Context, data, clientID, zoneID []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, encryptOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.Encrypt(ctx, data, clientID, zoneID)
}

// EncryptSearchable generate AcraStruct using passed ZoneID if length > 0 otherwise use ClientID (that is required after that) and searchable hash
func (wrapper *prometheusWrapper) EncryptSearchable(ctx context.Context, data, clientID, zoneID []byte) (SearchableResponse, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, encryptSearchableOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.EncryptSearchable(ctx, data, clientID, zoneID)
}

// DecryptSearchable decrypt AcraStruct using passed ZoneID if length > 0 otherwise use ClientID (that is required after that) and then verify hash
func (wrapper *prometheusWrapper) DecryptSearchable(ctx context.Context, data, hash, clientID, zoneID []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, decryptSearchableOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.DecryptSearchable(ctx, data, hash, clientID, zoneID)
}

// GenerateQueryHash generates searchable hash for data
func (wrapper *prometheusWrapper) GenerateQueryHash(ctx context.Context, data, clientID, zoneID []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, generateQueryHashOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.GenerateQueryHash(ctx, data, clientID, zoneID)
}

// Tokenize data from request according to TokenType using passed ZoneID if length > 0 otherwise use ClientID (that is required after that)
func (wrapper *prometheusWrapper) Tokenize(ctx context.Context, data interface{}, dataType tokenCommon.TokenType, clientID, zoneID []byte) (interface{}, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, tokenizeOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.Tokenize(ctx, data, dataType, clientID, zoneID)
}

// Detokenize data from request according to TokenType using passed ZoneID if length > 0 otherwise use ClientID (that is required after that)
func (wrapper *prometheusWrapper) Detokenize(ctx context.Context, data interface{}, dataType tokenCommon.TokenType, clientID, zoneID []byte) (interface{}, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, detokenizeOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.Detokenize(ctx, data, dataType, clientID, zoneID)
}

// EncryptSymSearchable encrypts data with AcraBlock using passed ZoneID if length > 0 otherwise use ClientID (that is required after that) and searchable hash
func (wrapper *prometheusWrapper) EncryptSymSearchable(ctx context.Context, data, clientID, zoneID []byte) (SearchableResponse, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, encryptSymSearchableOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.EncryptSymSearchable(ctx, data, clientID, zoneID)
}

// DecryptSymSearchable decrypt AcraBlock using passed ZoneID if length > 0 otherwise use ClientID (that is required after that) and verify hash
func (wrapper *prometheusWrapper) DecryptSymSearchable(ctx context.Context, data, hash, clientID, zoneID []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, decryptSymSearchableOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.DecryptSymSearchable(ctx, data, hash, clientID, zoneID)
}

// EncryptSym encrypts data with AcraBlock using passed ZoneID if length > 0 otherwise use ClientID (that is required after that)
func (wrapper *prometheusWrapper) EncryptSym(ctx context.Context, data, clientID, zoneID []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, encryptSymOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.EncryptSym(ctx, data, clientID, zoneID)
}

// DecryptSym decrypts AcraBlock using passed ZoneID if length > 0 otherwise use ClientID (that is required after that)
func (wrapper *prometheusWrapper) DecryptSym(ctx context.Context, acraBlock, clientID, zoneID []byte) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(RequestProcessingTimeHistogram.WithLabelValues(wrapper.metricType, decryptSymOperation).Observe))
	defer timer.ObserveDuration()
	return wrapper.ITranslatorService.DecryptSym(ctx, acraBlock, clientID, zoneID)
}
