package base

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
)

// Labels and values about AcraStruct decryptions status
const (
	DecryptionTypeLabel   = "status"
	DecryptionTypeSuccess = "success"
	DecryptionTypeFail    = "fail"
)

// Labels and values about data encryption status
const (
	EncryptionTypeLabel   = "status"
	EncryptionTypeSuccess = "success"
	EncryptionTypeFail    = "fail"
)

// Labels and values about db type in processing
const (
	DecryptionDBLabel      = "db"
	DecryptionDBPostgresql = "postgresql"
	DecryptionDBMysql      = "mysql"
)

var (
	// AcrastructDecryptionCounter collect decryptions count success/failed
	AcrastructDecryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_acrastruct_decryptions_total",
			Help: "number of AcraStruct decryptions",
		}, []string{DecryptionTypeLabel})

	// APIEncryptionCounter collect encryptions count success/failed
	APIEncryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_api_encryptions_total",
			Help: "number of encryptions data to AcraStruct",
		}, []string{EncryptionTypeLabel})

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

var dbRegisterLock = sync.Once{}
var acraStructRegisterLock = sync.Once{}

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
