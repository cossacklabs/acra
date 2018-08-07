package base

import "github.com/prometheus/client_golang/prometheus"

const (
	DecryptionTypeLabel   = "status"
	DecryptionTypeSuccess = "success"
	DecryptionTypeFail    = "fail"
)

var (
	AcrastructDecryptionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "acra_acrastruct_decryption_count",
			Help: "number of AcraStruct decryptions",
		}, []string{DecryptionTypeLabel})
)

func init() {
	prometheus.MustRegister(AcrastructDecryptionCounter)
}
