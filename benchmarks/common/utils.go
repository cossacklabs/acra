package common

import (
	data_rand "crypto/rand"
	"math/rand"
)

const (
	// db size will be 100kb * 100000 = 1000mb
	MAX_DATA_LENGTH = 100 * 1024 // 100 kb
)

func GenerateData() ([]byte, error) {
	length := rand.Intn(MAX_DATA_LENGTH)
	data := make([]byte, length)
	_, err := data_rand.Read(data)
	return data, err
}
