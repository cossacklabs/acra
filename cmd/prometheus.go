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
	"fmt"
	"github.com/cossacklabs/acra/logging"
	"github.com/cossacklabs/acra/network"
	"github.com/cossacklabs/acra/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
	"strings"
	"sync"
)

// RunPrometheusHTTPHandler run in goroutine http server that process with connectionString address and export
// prometheus metrics
func RunPrometheusHTTPHandler(connectionString string) (net.Listener, *http.Server, error) {
	listener, err := network.Listen(connectionString)
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{ReadTimeout: network.DefaultNetworkTimeout, WriteTimeout: network.DefaultNetworkTimeout}
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		logrus.WithField("connection_string", connectionString).Infoln("Start prometheus http handler")
		err := server.Serve(listener)
		if err != nil {
			logrus.WithField(logging.FieldKeyEventCode, logging.EventCodeErrorPrometheusHTTPHandler).WithError(err).Errorln("Error from HTTP server that process prometheus metrics")
		}
	}()
	return listener, server, nil
}

var registerLock = sync.Once{}

// serviceNameToLabelFormat convert service name to lower case and remove all '_'
// ex. Acra-Server will be changed to acraserver
func serviceNameToLabelFormat(serviceName string) string {
	const replaceAll = -1
	return strings.ToLower(strings.Replace(serviceName, "-", "", replaceAll))
}

// ExportVersionMetric set values for version metrics
func ExportVersionMetric(version *utils.Version) {
	version, err := utils.GetParsedVersion()
	if err != nil {
		panic(err)
	}

	if majorVersionGauge == nil || minorVersionGauge == nil || patchVersionGauge == nil {
		panic("call RegisterVersionMetrics before exporting to initialize and register metrics")
	}

	val, _ := version.MajorAsFloat64()
	majorVersionGauge.With(nil).Set(val)

	val, _ = version.MinorAsFloat64()
	minorVersionGauge.With(nil).Set(val)

	val, _ = version.PatchAsFloat64()
	patchVersionGauge.With(nil).Set(val)
}

var (
	majorVersionGauge *prometheus.GaugeVec
	minorVersionGauge *prometheus.GaugeVec
	patchVersionGauge *prometheus.GaugeVec
)

// RegisterVersionMetrics set and register metrics with current version value
func RegisterVersionMetrics(serviceName string) {
	labelServiceName := serviceNameToLabelFormat(serviceName)
	majorVersionGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_version_major", labelServiceName),
			Help: "Major number of version",
		}, []string{})

	minorVersionGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_version_minor", labelServiceName),
			Help: "Minor number of version",
		}, []string{})

	patchVersionGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_version_patch", labelServiceName),
			Help: "Patch number of version",
		}, []string{})

	registerLock.Do(func() {
		prometheus.MustRegister(majorVersionGauge)
		prometheus.MustRegister(minorVersionGauge)
		prometheus.MustRegister(patchVersionGauge)
	})
}
