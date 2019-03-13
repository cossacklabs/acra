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

// serviceNameToLabelFormat convert service name to lower case and remove all '_'
// ex. Acra-Server will be changed to acraserver
func serviceNameToLabelFormat(serviceName string) string {
	const replaceAll = -1
	return strings.ToLower(strings.Replace(serviceName, "-", "", replaceAll))
}

// editionToLabel convert edition value to string to use as label
func editionToLabel(edition utils.ProductEdition) string {
	switch edition {
	case utils.CommunityEdition:
		return "ce"
	case utils.EnterpriseEdition:
		return "ee"
	}
	panic(fmt.Sprintf("undefined edition: %v", edition))
}

// exportVersionMetric set values for version metrics
func exportVersionMetric(version *utils.Version) {
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
	buildInfoCounter  *prometheus.CounterVec
)

const (
	BuildInfoEditionLabel = "edition"
	BuildInfoVersionLabel = "version"
)

var registerVersionMetricsLock = sync.Once{}

// RegisterVersionMetrics set and register metrics with current version value
func RegisterVersionMetrics(serviceName string, version *utils.Version) {
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

	registerVersionMetricsLock.Do(func() {
		prometheus.MustRegister(majorVersionGauge)
		prometheus.MustRegister(minorVersionGauge)
		prometheus.MustRegister(patchVersionGauge)
		exportVersionMetric(version)
	})
}

var registerBuildInfoLock = sync.Once{}

// RegisterBuildInfoMetrics set and register metrics with build info
func RegisterBuildInfoMetrics(serviceName string, edition utils.ProductEdition) {
	buildInfoCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_build_info", serviceNameToLabelFormat(serviceName)),
		}, []string{BuildInfoEditionLabel, BuildInfoVersionLabel})

	registerBuildInfoLock.Do(func() {
		prometheus.MustRegister(buildInfoCounter)
		version, err := utils.GetParsedVersion()
		if err != nil {
			panic(err)
		}
		// increment on start only once
		buildInfoCounter.With(prometheus.Labels{BuildInfoEditionLabel: editionToLabel(edition), BuildInfoVersionLabel: version.String()}).Inc()
	})
}
