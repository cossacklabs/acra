package base

import "github.com/prometheus/client_golang/prometheus"

var (
	AcrastructDecryptionCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "acra_acrastruct_decryption_count",
			Help: "number of AcraStruct decryptions",
		})
)

func init() {
	prometheus.MustRegister(AcrastructDecryptionCounter)
}
