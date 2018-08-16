package base

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
)

const (
	DecryptionTypeLabel   = "status"
	DecryptionTypeSuccess = "success"
	DecryptionTypeFail    = "fail"
)
const (
	DecryptionModeLabel  = "mode"
	DecryptionModeWhole  = "wholecell"
	DecryptionModeInline = "inlinecell"
)

const (
	DecryptionDBLabel      = "db"
	DecryptionDBPostgresql = "postgresql"
	DecryptionDBMysql      = "mysql"
)

var (
	AcrastructDecryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_acrastruct_decryptions_total",
			Help: "number of AcraStruct decryptions",
		}, []string{DecryptionTypeLabel})

	ResponseProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acraserver_response_processing_seconds_bucket",
		Help:    "Time of response processing",
		Buckets: []float64{0.000001, 0.00001, 0.00002, 0.00003, 0.00004, 0.00005, 0.00006, 0.00007, 0.00008, 0.00009, 0.0001, 0.0005, 0.001, 0.005, 0.01, 1},
	}, []string{DecryptionDBLabel, DecryptionModeLabel})

	RequestProcessingTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "acraserver_request_processing_seconds_bucket",
		Help:    "Time of response processing",
		Buckets: []float64{0.000001, 0.00001, 0.00002, 0.00003, 0.00004, 0.00005, 0.00006, 0.00007, 0.00008, 0.00009, 0.0001, 0.0005, 0.001, 0.005, 0.01, 1},
	}, []string{DecryptionDBLabel})
)

var dbRegisterLock = sync.Once{}
var acraStructRegisterLock = sync.Once{}

func RegisterDbProcessingMetrics() {
	dbRegisterLock.Do(func() {
		prometheus.MustRegister(ResponseProcessingTimeHistogram)
		prometheus.MustRegister(RequestProcessingTimeHistogram)
	})
}
func RegisterAcraStructProcessingMetrics() {
	acraStructRegisterLock.Do(func() {
		prometheus.MustRegister(AcrastructDecryptionCounter)
	})

}
