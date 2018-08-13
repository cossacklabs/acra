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
package cmd

import (
	"github.com/cossacklabs/acra/network"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
)

// RunPrometheusHTTPHandler run in goroutine http server that process with connectionString address and export
// prometheus metrics
func RunPrometheusHTTPHandler(connectionString string) (net.Listener, error) {
	listener, err := network.Listen(connectionString)
	if err != nil {
		return nil, err
	}
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		logrus.WithField("connection_string", connectionString).Infoln("Start prometheus http handler")
		err := http.Serve(listener, nil)
		if err != nil {
			logrus.WithError(err).Errorln("Error from http server that process prometheus metrics")
		}
	}()
	return listener, nil
}
