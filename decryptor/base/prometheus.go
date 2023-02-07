package base

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// LabelStatus base constants for prometheus metrics
const (
	LabelStatus        = "status"
	LabelStatusFail    = "fail"
	LabelStatusSuccess = "success"

	LabelType                 = "type"
	LabelTypeAcraBlock        = "acrablock"
	LabelTypeAcraStruct       = "acrastruct"
	LabelTypeAcraBlockSearch  = "acrablock_searchable"
	LabelTypeAcraStructSearch = "acrastruct_searchable"

	LabelTokenType = "token_type"
)

// Labels and values about db type in processing
const (
	DecryptionDBLabel      = "db"
	DecryptionDBPostgresql = "postgresql"
	DecryptionDBMysql      = "mysql"
)

// Deprecated Metrics
var (
	// AcrastructDecryptionCounter collect decryptions count success/failed
	AcrastructDecryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_acrastruct_decryptions_total",
			Help: "number of AcraStruct decryptions",
		}, []string{LabelStatus})

	// APIEncryptionCounter collect encryptions count success/failed
	APIEncryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_api_encryptions_total",
			Help: "number of encryptions data to AcraStruct",
		}, []string{LabelStatus})
)

var (

	// AcraDecryptionCounter collect decryptions count success/failed for type acrablock/acrastruct
	AcraDecryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_decryptions_total",
			Help: "number of decryptions AcraStruct/AcraBlock",
		}, []string{LabelStatus, LabelType})

	// AcraEncryptionCounter collect encryptions count success/failed for type acrablock/acrastruct
	AcraEncryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_encryptions_total",
			Help: "number of encryptions AcraStruct/AcraBlock",
		}, []string{LabelStatus, LabelType})

	// AcraTokenizationCounter collect tokenizations count success/failed for token_type
	AcraTokenizationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_tokenizations_total",
			Help: "number of tokenizations for token_type",
		}, []string{LabelStatus, LabelTokenType})

	// AcraDetokenizationCounter collect tokenizations count success/failed  for token_type
	AcraDetokenizationCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_detokenization_total",
			Help: "number of detokenizations for token_type",
		}, []string{LabelStatus, LabelTokenType})

	// ResponseProcessingTimeHistogram collect metrics about response processing time
	ResponseProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acraserver_response_processing_seconds",
		Help:    "Time of response processing",
		Buckets: []float64{0.000001, 0.00001, 0.00002, 0.00003, 0.00004, 0.00005, 0.00006, 0.00007, 0.00008, 0.00009, 0.0001, 0.0005, 0.001, 0.005, 0.01, 1, 3, 5, 10},
	}, []string{DecryptionDBLabel})

	// RequestProcessingTimeHistogram collect metrics about request processing time
	RequestProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acraserver_request_processing_seconds",
		Help:    "Time of response processing",
		Buckets: []float64{0.000001, 0.00001, 0.00002, 0.00003, 0.00004, 0.00005, 0.00006, 0.00007, 0.00008, 0.00009, 0.0001, 0.0005, 0.001, 0.005, 0.01, 1, 3, 5, 10},
	}, []string{DecryptionDBLabel})
)

var (
	dbRegisterLock                   = sync.Once{}
	acraStructRegisterLock           = sync.Once{}
	encryptionDecryptionRegisterLock = sync.Once{}
	tokenizationRegisterLock         = sync.Once{}
)

// RegisterDbProcessingMetrics register in default prometheus registry metrics related with processing db requests/responses
func RegisterDbProcessingMetrics() {
	dbRegisterLock.Do(func() {
		prometheus.MustRegister(ResponseProcessingTimeHistogram)
		prometheus.MustRegister(RequestProcessingTimeHistogram)
	})
}

// RegisterAcraStructProcessingMetrics register in default prometheus registry metrics related with AcraStruct decryption
func RegisterAcraStructProcessingMetrics() {
	acraStructRegisterLock.Do(func() {
		prometheus.MustRegister(AcrastructDecryptionCounter)
		prometheus.MustRegister(APIEncryptionCounter)
	})
}

// RegisterEncryptionDecryptionProcessingMetrics register in default prometheus registry metrics related with AcraBlock/AcraStruct decryption/encryption
func RegisterEncryptionDecryptionProcessingMetrics() {
	encryptionDecryptionRegisterLock.Do(func() {
		prometheus.MustRegister(AcraDecryptionCounter)
		prometheus.MustRegister(AcraEncryptionCounter)
	})
}

// RegisterTokenizationProcessingMetrics register in default prometheus registry metrics related with tokenization/detokenization
func RegisterTokenizationProcessingMetrics() {
	tokenizationRegisterLock.Do(func() {
		prometheus.MustRegister(AcraTokenizationCounter)
		prometheus.MustRegister(AcraDetokenizationCounter)
	})
}
